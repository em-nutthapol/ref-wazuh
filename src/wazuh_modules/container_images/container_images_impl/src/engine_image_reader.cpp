/*
 * Wazuh Module for Container Images
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "engine_image_reader.hpp"

#include "archive_image_reader.hpp"
#include "ci_logging_helper.hpp"
#include "oci_metadata.hpp"
#include "registry_reference.hpp"

#include <algorithm>
#include <exception>
#include <map>
#include <set>
#include <utility>

namespace
{
    void logDebug(const std::string& message)
    {
        LoggingHelper::getInstance().log(LOG_DEBUG, message);
    }

    void logWarn(const std::string& message)
    {
        LoggingHelper::getInstance().log(LOG_WARNING, message);
    }

    /// @brief An export stream that adds the bytes it delivered to the scan's count when it is closed.
    ///
    /// The count is what the per-scan allowance is checked against, and an export is read twice,
    /// once for the metadata and once for the layers, so each pass is charged.
    class MeteredStream final : public containerimages::IBlobStream
    {
        public:
            MeteredStream(std::unique_ptr<containerimages::IBlobStream> stream, std::uint64_t* scanBytes)
                : m_stream {std::move(stream)}
                , m_scanBytes {scanBytes}
            {
            }

            ~MeteredStream() override
            {
                if (m_scanBytes != nullptr)
                {
                    *m_scanBytes += m_stream->bytesDelivered();
                }
            }

            std::size_t read(char* buffer, const std::size_t size) override
            {
                return m_stream->read(buffer, size);
            }

            bool failed() const override
            {
                return m_stream->failed();
            }

            const std::string& error() const override
            {
                return m_stream->error();
            }

            long status() const override
            {
                return m_stream->status();
            }

            std::uint64_t bytesDelivered() const override
            {
                return m_stream->bytesDelivered();
            }

            bool abortedLocally() const override
            {
                return m_stream->abortedLocally();
            }

            const std::string& retryAfter() const override
            {
                return m_stream->retryAfter();
            }

        private:
            std::unique_ptr<containerimages::IBlobStream> m_stream;
            std::uint64_t* m_scanBytes;
    };

    /// @brief Every digest the image is known by: what its names pin it to, then its configuration,
    /// then the engine's own id when that is neither (an engine that identifies an image by its manifest).
    std::vector<std::string> digestsOf(const containerimages::EngineImage& image, const std::string& configDigest)
    {
        std::vector<std::string> pinned;

        for (const auto& repoDigest : image.repoDigests)
        {
            const auto at {repoDigest.find('@')};

            if (at != std::string::npos && containerimages::oci::isHexDigest(repoDigest.substr(at + 1)))
            {
                pinned.push_back(repoDigest.substr(at + 1));
            }
        }

        auto digests {containerimages::oci::collectDigests(pinned, "", configDigest)};

        if (std::find(digests.begin(), digests.end(), image.id) == digests.end())
        {
            digests.push_back(image.id);
        }

        return digests;
    }

    /// @brief The name and tags of an image: those of its tags, and for an image pulled by digest, which has
    /// none, the repository its digest names. The tags of that case are empty, since the digest says none.
    containerimages::ImageNames namesOf(const containerimages::EngineImage& image)
    {
        auto names {containerimages::imageNamesOf(image.repoTags)};

        for (const auto& repoDigest : image.repoDigests)
        {
            if (!names.name.empty())
            {
                break;
            }

            containerimages::NormalizedImageName normalized;

            if (containerimages::normalizeImageName(repoDigest.substr(0, repoDigest.find('@')), normalized))
            {
                names.name = normalized.name;
            }
        }

        return names;
    }

    /// @brief True when the stored record is of this image: its configuration, or any digest it was known by, is the engine's id.
    bool holdsImage(const containerimages::ImageReferenceRecord& stored, const std::string& id)
    {
        return stored.configDigest == id || std::find(stored.digests.begin(), stored.digests.end(), id) != stored.digests.end();
    }
} // namespace

namespace containerimages
{
    EngineImageReader::EngineImageReader(std::string engine, std::shared_ptr<IEngineImageSource> source, ReaderContext context)
        : m_engine {std::move(engine)}
        , m_source {std::move(source)}
        , m_context {context}
    {
    }

    std::string EngineImageReader::sourceType() const
    {
        return referenceTypeName(ReferenceType::EngineStore);
    }

    ImageReadResult EngineImageReader::discover()
    {
        // Same rule as the other readers: nothing escapes to the scan loop, which runs on the module thread.
        try
        {
            std::vector<EngineImage> images;
            std::string error;

            if (!m_source->listImages(images, error))
            {
                logWarn("The '" + m_engine + "' engine could not be read: " + error + ". The images stored for it are kept.");
                return ImageReadResult::failed();
            }

            std::map<std::string, const ImageReferenceRecord*> stored;

            if (m_context.storedEngineImages != nullptr)
            {
                for (const auto& record : *m_context.storedEngineImages)
                {
                    stored.emplace(record.source.location, &record);
                }
            }

            std::vector<ImageReferenceRecord> records;
            std::set<std::string> seen;

            for (const auto& image : images)
            {
                if (m_context.stopRequested != nullptr && m_context.stopRequested->load())
                {
                    logDebug("Stop requested, leaving the images of the '" + m_engine + "' engine.");
                    return ImageReadResult::failed();
                }

                // The id is a key, a path of the export request and the identity of the row: a value that
                // is not a digest is not an image this module can name.
                if (!oci::isHexDigest(image.id))
                {
                    logDebug("Ignoring an image of the '" + m_engine + "' engine with the id '" + image.id.substr(0, 80) +
                             "': it is not a digest.");
                    continue;
                }

                const auto key {m_engine + "/" + image.id};

                if (!seen.insert(key).second)
                {
                    continue;
                }

                const auto known {stored.find(key)};
                auto record {readImage(image, key, known != stored.end() ? known->second : nullptr)};

                if (record)
                {
                    records.push_back(std::move(*record));
                }
            }

            // Forget the oversize images the engine no longer lists, so the set follows the engine.
            if (m_context.reportedOversizeImages != nullptr)
            {
                for (auto reported = m_context.reportedOversizeImages->begin(); reported != m_context.reportedOversizeImages->end();)
                {
                    reported = std::any_of(images.begin(), images.end(), [&reported](const EngineImage & image)
                    {
                        return image.id == *reported;
                    }) ? std::next(reported) : m_context.reportedOversizeImages->erase(reported);
                }
            }

            return ImageReadResult::success(std::move(records));
        }
        catch (const std::exception& ex)
        {
            logWarn("Could not read the '" + m_engine + "' engine: " + ex.what());
        }
        catch (...)
        {
            logWarn("Could not read the '" + m_engine + "' engine: unknown error.");
        }

        return ImageReadResult::failed();
    }

    std::optional<ImageReferenceRecord> EngineImageReader::readImage(const EngineImage& image,
                                                                     const std::string& key,
                                                                     const ImageReferenceRecord* stored)
    {
        const auto names {namesOf(image)};

        // What the engine says about an image now, which holds for a record read this time and for one
        // carried over: its names and digests can change while its contents do not.
        const auto describe = [&](ImageReferenceRecord record)
        {
            record.source = {referenceTypeName(ReferenceType::EngineStore), key};
            record.name = names.name;
            record.tags = names.tags;
            record.digests = digestsOf(image, record.configDigest);
            return record;
        };

        if (stored != nullptr && holdsImage(*stored, image.id))
        {
            logDebug("Image '" + key + "' is the one already stored, so it was not exported again.");
            return describe(*stored);
        }

        const auto carry = [&]() -> std::optional<ImageReferenceRecord>
        {
            if (stored == nullptr)
            {
                return std::nullopt;
            }

            logWarn("Image '" + key + "' could not be read. Keeping the " + std::to_string(stored->packages.size()) +
                    " package(s) already stored for it, which are left as they were.");
            return describe(*stored);
        };

        const RegistryLimits limits {m_context.config != nullptr ? m_context.config->limits : RegistryLimits {}};

        // The engine says how big an image is, so one over the allowance is not exported at all: reading it
        // would end at the stream's ceiling, after spending up to that much of the scan allowance on an image
        // that is stored nowhere, and the next scan would do the same. The ceiling on the stream stays for a
        // listing that under-reports. Said once per image, not once per scan.
        if (image.size > limits.maxImageBytes)
        {
            if (m_context.reportedOversizeImages == nullptr || m_context.reportedOversizeImages->insert(image.id).second)
            {
                logWarn("Image '" + key + "' was not read: the engine reports " + std::to_string(image.size) +
                        " bytes, over the " + std::to_string(limits.maxImageBytes) + " byte allowance of an image.");
            }

            return stored != nullptr ? std::optional<ImageReferenceRecord> {describe(*stored)} :
                   std::nullopt;
        }

        if (m_context.scanBytes != nullptr && *m_context.scanBytes >= limits.maxScanBytes)
        {
            // Checked before an image is started, like a registry reference, so the scan stops taking on
            // new work instead of abandoning an image halfway.
            if (!m_scanAllowanceLogged)
            {
                logWarn("The remaining images of the '" + m_engine + "' engine were not read: this scan already reached its " +
                        std::to_string(limits.maxScanBytes) + " byte allowance.");
                m_scanAllowanceLogged = true;
            }

            return carry();
        }

        const ArchiveOpener open = [&]() -> std::unique_ptr<IByteStream>
        {
            std::string error;
            auto stream {m_source->exportImage(image.id, limits.maxImageBytes, error)};

            if (!stream)
            {
                logWarn("Image '" + key + "' could not be exported: " + error + ".");
                return nullptr;
            }

            return std::make_unique<MeteredStream>(std::move(stream), m_context.scanBytes);
        };

        // The archive reader skips the layers when the configuration it finds is the stored one, which
        // covers an engine whose id is not the configuration digest.
        ArchiveImageReader reader {key, stored != nullptr ? stored->configDigest : std::string {}, m_context.stopRequested, open};
        auto result {reader.discover()};

        if (result.status == ReadStatus::Unchanged && stored != nullptr)
        {
            return describe(*stored);
        }

        if (result.status != ReadStatus::Success || result.records.empty())
        {
            return carry();
        }

        return describe(std::move(result.records.front()));
    }
} // namespace containerimages
