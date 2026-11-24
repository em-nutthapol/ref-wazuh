#include "container_baseline.h"
#include "image_source_files.hpp"

#include <gtest/gtest.h>

#include <string>

using wazuh::container_baseline::ImageSourceFiles;
using wazuh::container_baseline::ImageSourceKind;

// The C export is what syscollector builds its trigger list from; it has to
// describe the same files the fingerprint reads. Compared as strings: this
// binary links the table twice, once directly and once through the library.
TEST(ImageSourceFiles, TheCExportMatchesTheTable)
{
    std::size_t expected = 0;
    const auto* files = ImageSourceFiles(expected);

    std::size_t count = 0;
    const auto* exported = cbaseline_source_files(&count);

    ASSERT_NE(exported, nullptr);
    ASSERT_EQ(count, expected);

    for (std::size_t i = 0; i < count; ++i)
    {
        EXPECT_EQ(std::string(exported[i].path), std::string(files[i].path));
        EXPECT_EQ(exported[i].classes, files[i].classes);

        const int kind = files[i].kind == ImageSourceKind::directory ? CB_SOURCE_KIND_DIRECTORY
                         : files[i].kind == ImageSourceKind::wal     ? CB_SOURCE_KIND_WAL
                         : CB_SOURCE_KIND_FILE;
        EXPECT_EQ(exported[i].kind, kind) << files[i].path;
    }
}

TEST(ImageSourceFiles, TheRpmWriteAheadLogsAreListedAsWal)
{
    std::size_t count = 0;
    const auto* files = ImageSourceFiles(count);
    std::size_t wal = 0;

    for (std::size_t i = 0; i < count; ++i)
    {
        const std::string path {files[i].path};
        const bool isWal = path.size() > 4 && path.compare(path.size() - 4, 4, "-wal") == 0;
        EXPECT_EQ(isWal, files[i].kind == ImageSourceKind::wal) << path;
        wal += isWal ? 1 : 0;
    }

    EXPECT_EQ(wal, 2u);
}
