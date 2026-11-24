/*
 * Wazuh SysCollector
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _CONTAINER_FRESHNESS_HPP
#define _CONTAINER_FRESHNESS_HPP

#include <chrono>
#include <functional>
#include <map>
#include <set>
#include <string>
#include <utility>
#include <vector>

/// Inventory classes a source feeds; the same bits as container_baseline's
/// CB_SOURCE_*.
constexpr unsigned CONTAINER_SOURCE_PACKAGES = 1u << 0;
constexpr unsigned CONTAINER_SOURCE_USERS    = 1u << 1;
constexpr unsigned CONTAINER_SOURCE_OS       = 1u << 2;

/// A file a container's inventory is read from, as container_baseline exports
/// it. Its own type so this header builds where container_baseline does not.
struct FreshnessSource
{
    std::string path;
    unsigned    classes {0};
    /// The files directly inside it are the sources.
    bool        directory {false};
};

/// Whether a file event at `path`, inside a container, touched one of its
/// inventory sources of an enabled class. Exact: the kernel filters on bare
/// names, and `status`, `group` or `installed` are common ones.
[[nodiscard]] inline bool isSourcePath(const std::vector<FreshnessSource>& sources,
                                       const std::string& path,
                                       unsigned enabledClasses)
{
    // An image where /lib links to usr/lib reports the resolved path.
    static const std::string usrLib {"/usr/lib/"};
    const std::string alias = path.compare(0, usrLib.size(), usrLib) == 0 ? path.substr(4) : std::string {};
    const std::string* const candidates[] = {&path, &alias};

    for (const auto& source : sources)
    {
        if ((source.classes & enabledClasses) == 0)
        {
            continue;
        }

        for (const auto* candidate : candidates)
        {
            if (candidate->empty())
            {
                continue;
            }

            if (!source.directory)
            {
                if (*candidate == source.path)
                {
                    return true;
                }

                continue;
            }

            // A direct child, not a package's md5sums file.
            const auto& dir = source.path;

            if (candidate->size() > dir.size() + 1 && candidate->compare(0, dir.size(), dir) == 0 &&
                    (*candidate)[dir.size()] == '/' && candidate->find('/', dir.size() + 1) == std::string::npos)
            {
                static const std::string md5sums {".md5sums"};
                const bool isMd5sums = candidate->size() >= md5sums.size() &&
                                       candidate->compare(candidate->size() - md5sums.size(), md5sums.size(), md5sums) == 0;

                if (!isMd5sums)
                {
                    return true;
                }
            }
        }
    }

    return false;
}

/// The kernel name filter's two lists for the enabled classes: the file names
/// of the sources, and the names of the directories whose files are sources.
/// Each name once.
[[nodiscard]] inline std::pair<std::vector<std::string>, std::vector<std::string>> nameFilterLists(const std::vector<FreshnessSource>& sources,
                                                                                                   unsigned enabledClasses)
{
    std::set<std::string> files;
    std::set<std::string> parents;

    for (const auto& source : sources)
    {
        const auto slash = source.path.rfind('/');

        if ((source.classes & enabledClasses) == 0 || slash == std::string::npos || slash + 1 == source.path.size())
        {
            continue;
        }

        (source.directory ? parents : files).insert(source.path.substr(slash + 1));
    }

    return {{files.begin(), files.end()}, {parents.begin(), parents.end()}};
}

/// Which containers had a source written, and when each is due a refresh: a
/// quiet period after its last write, so a package manager rewriting its
/// database several times is walked once when it is done, and at most once per
/// gap, so a container that never stops writing cannot keep the scan thread
/// busy. Times are passed in; nothing here reads a clock.
class FreshnessMarks
{
    public:
        using Clock = std::chrono::steady_clock;

        FreshnessMarks(Clock::duration quiet, Clock::duration gap)
            : m_quiet(quiet), m_gap(gap)
        {
        }

        void mark(const std::string& containerId, Clock::time_point now)
        {
            auto& entry = m_entries[containerId];
            entry.dirty = true;
            entry.followUp = false;
            entry.dueAt = now + m_quiet;
        }

        /// The containers due now, stamped as requested. A due container
        /// `isAdmitted` refuses is dropped: its refresh would report nothing.
        ///
        /// Each refresh brings one follow-up a gap later: a writer that marks
        /// only the start of its work (rpm on BerkeleyDB) is read mid-way by
        /// the first, and its final state is read by the second.
        std::vector<std::string> takeDue(Clock::time_point now, const std::function<bool(const std::string&)>& isAdmitted)
        {
            std::vector<std::string> due;

            for (auto it = m_entries.begin(); it != m_entries.end();)
            {
                auto& entry = it->second;
                const bool gapElapsed = !entry.requested || now - entry.lastRequested >= m_gap;

                if (entry.dirty && entry.dueAt <= now && gapElapsed)
                {
                    const bool wasFollowUp = entry.followUp;
                    entry.dirty = false;
                    entry.followUp = false;

                    if (isAdmitted(it->first))
                    {
                        due.push_back(it->first);
                        entry.requested = true;
                        entry.lastRequested = now;

                        if (!wasFollowUp)
                        {
                            entry.dirty = true;
                            entry.followUp = true;
                            entry.dueAt = now + m_gap;
                        }
                    }
                }

                // Nothing pending and nothing left to space out.
                if (!entry.dirty && (!entry.requested || now - entry.lastRequested >= m_gap))
                {
                    it = m_entries.erase(it);
                }
                else
                {
                    ++it;
                }
            }

            return due;
        }

        void clear()
        {
            m_entries.clear();
        }

        [[nodiscard]] std::size_t size() const
        {
            return m_entries.size();
        }

    private:
        struct Entry
        {
            bool              dirty {false};
            /// The pending refresh is the follow-up of one already served.
            bool              followUp {false};
            Clock::time_point dueAt {};
            bool              requested {false};
            Clock::time_point lastRequested {};
        };

        Clock::duration               m_quiet;
        Clock::duration               m_gap;
        std::map<std::string, Entry> m_entries;
};

#endif // _CONTAINER_FRESHNESS_HPP
