/*
 * Wazuh SysCollector
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "containerFreshness.hpp"

#include <gtest/gtest.h>

#include <set>

namespace
{
    const std::vector<FreshnessSource> SOURCES
    {
        {"/etc/passwd", CONTAINER_SOURCE_USERS, false},
        {"/var/lib/dpkg/status", CONTAINER_SOURCE_PACKAGES, false},
        {"/var/lib/dpkg/status.d", CONTAINER_SOURCE_PACKAGES, true},
        {"/lib/apk/db/installed", CONTAINER_SOURCE_PACKAGES, false},
        {"/var/lib/rpm/rpmdb.sqlite-wal", CONTAINER_SOURCE_PACKAGES, false},
    };

    using Clock = FreshnessMarks::Clock;
    using std::chrono::seconds;

    const auto ADMIT_ALL = [](const std::string&)
    {
        return true;
    };
} // namespace

TEST(ContainerFreshnessPathTest, ASourceMatchesExactly)
{
    EXPECT_TRUE(isSourcePath(SOURCES, "/var/lib/dpkg/status", CONTAINER_SOURCE_PACKAGES));
    EXPECT_TRUE(isSourcePath(SOURCES, "/var/lib/rpm/rpmdb.sqlite-wal", CONTAINER_SOURCE_PACKAGES));
    EXPECT_FALSE(isSourcePath(SOURCES, "/var/lib/dpkg/status-new", CONTAINER_SOURCE_PACKAGES));
    EXPECT_FALSE(isSourcePath(SOURCES, "/app/status", CONTAINER_SOURCE_PACKAGES))
            << "the kernel matches bare names; another file named status is not a source";
}

TEST(ContainerFreshnessPathTest, AResolvedUsrLibPathMatchesItsLibSource)
{
    EXPECT_TRUE(isSourcePath(SOURCES, "/usr/lib/apk/db/installed", CONTAINER_SOURCE_PACKAGES));
    EXPECT_FALSE(isSourcePath(SOURCES, "/usr/lib/apk/db/other", CONTAINER_SOURCE_PACKAGES));
}

TEST(ContainerFreshnessPathTest, OnlyADirectSourceDirectoryChildMatches)
{
    EXPECT_TRUE(isSourcePath(SOURCES, "/var/lib/dpkg/status.d/base-files", CONTAINER_SOURCE_PACKAGES));
    EXPECT_FALSE(isSourcePath(SOURCES, "/var/lib/dpkg/status.d/base-files.md5sums", CONTAINER_SOURCE_PACKAGES));
    EXPECT_FALSE(isSourcePath(SOURCES, "/var/lib/dpkg/status.d/sub/x", CONTAINER_SOURCE_PACKAGES));
    EXPECT_FALSE(isSourcePath(SOURCES, "/var/lib/dpkg/status.d", CONTAINER_SOURCE_PACKAGES));
    EXPECT_FALSE(isSourcePath(SOURCES, "/var/lib/dpkg/status.dx/a", CONTAINER_SOURCE_PACKAGES));
}

TEST(ContainerFreshnessPathTest, ADisabledClassNeverMatches)
{
    EXPECT_FALSE(isSourcePath(SOURCES, "/etc/passwd", CONTAINER_SOURCE_PACKAGES));
    EXPECT_TRUE(isSourcePath(SOURCES, "/etc/passwd", CONTAINER_SOURCE_USERS));
    EXPECT_FALSE(isSourcePath(SOURCES, "/var/lib/dpkg/status", 0));
}

TEST(ContainerFreshnessMarksTest, AContainerIsDueAQuietPeriodAfterItsLastWrite)
{
    FreshnessMarks marks {seconds{5}, seconds{30}};
    const auto t0 = Clock::time_point {} + seconds{1000};

    marks.mark("a", t0);
    EXPECT_TRUE(marks.takeDue(t0 + seconds{4}, ADMIT_ALL).empty());

    // A package manager rewriting its database pushes the refresh back.
    marks.mark("a", t0 + seconds{4});
    EXPECT_TRUE(marks.takeDue(t0 + seconds{8}, ADMIT_ALL).empty());
    EXPECT_EQ(marks.takeDue(t0 + seconds{9}, ADMIT_ALL), (std::vector<std::string> {"a"}));
    EXPECT_TRUE(marks.takeDue(t0 + seconds{10}, ADMIT_ALL).empty()) << "served once";
}

TEST(ContainerFreshnessMarksTest, AContainerIsRefreshedAtMostOncePerGapAndKeepsItsMark)
{
    FreshnessMarks marks {seconds{5}, seconds{30}};
    const auto t0 = Clock::time_point {} + seconds{1000};

    marks.mark("a", t0);
    ASSERT_EQ(marks.takeDue(t0 + seconds{5}, ADMIT_ALL), (std::vector<std::string> {"a"}));

    marks.mark("a", t0 + seconds{10});
    EXPECT_TRUE(marks.takeDue(t0 + seconds{20}, ADMIT_ALL).empty()) << "inside the gap";
    EXPECT_EQ(marks.takeDue(t0 + seconds{35}, ADMIT_ALL), (std::vector<std::string> {"a"}))
            << "the write inside the gap is not lost, only held";
}

TEST(ContainerFreshnessMarksTest, AContainerThatNeverStopsWritingIsStillRefreshedOncePerGap)
{
    FreshnessMarks marks {seconds{5}, seconds{30}};
    const auto t0 = Clock::time_point {} + seconds{1000};
    std::vector<seconds> refreshedAt;

    // A write every 2 s never leaves a quiet period.
    for (seconds t {0}; t <= seconds{70}; t += seconds{2})
    {
        marks.mark("a", t0 + t);

        if (!marks.takeDue(t0 + t, ADMIT_ALL).empty())
        {
            refreshedAt.push_back(t);
        }
    }

    EXPECT_EQ(refreshedAt, (std::vector<seconds> {seconds{30}, seconds{62}}));
}

TEST(ContainerFreshnessMarksTest, ContainersAreIndependent)
{
    FreshnessMarks marks {seconds{5}, seconds{30}};
    const auto t0 = Clock::time_point {} + seconds{1000};

    marks.mark("a", t0);
    marks.mark("b", t0);
    marks.mark("a", t0 + seconds{1});
    const auto due = marks.takeDue(t0 + seconds{6}, ADMIT_ALL);
    EXPECT_EQ(std::set<std::string>(due.begin(), due.end()), (std::set<std::string> {"a", "b"}));
}

TEST(ContainerFreshnessMarksTest, ANonAdmittedContainerIsDroppedNotRefreshed)
{
    FreshnessMarks marks {seconds{5}, seconds{30}};
    const auto t0 = Clock::time_point {} + seconds{1000};

    marks.mark("refused", t0);
    marks.mark("a", t0);
    const auto due = marks.takeDue(t0 + seconds{5}, [](const std::string & id)
    {
        return id != "refused";
    });
    EXPECT_EQ(due, (std::vector<std::string> {"a"}));
    EXPECT_EQ(marks.takeDue(t0 + seconds{40}, ADMIT_ALL), (std::vector<std::string> {"a"}))
            << "a's follow-up only: the refused mark is gone, not deferred";
}

TEST(ContainerFreshnessMarksTest, SettledContainersArePruned)
{
    FreshnessMarks marks {seconds{5}, seconds{30}};
    const auto t0 = Clock::time_point {} + seconds{1000};

    marks.mark("a", t0);
    ASSERT_EQ(marks.takeDue(t0 + seconds{5}, ADMIT_ALL).size(), 1u);
    ASSERT_EQ(marks.takeDue(t0 + seconds{35}, ADMIT_ALL).size(), 1u) << "the follow-up";
    EXPECT_EQ(marks.size(), 1u) << "kept while its gap runs";
    static_cast<void>(marks.takeDue(t0 + seconds{70}, ADMIT_ALL));
    EXPECT_EQ(marks.size(), 0u);
}

TEST(ContainerFreshnessMarksTest, ARefreshBringsOneFollowUpAGapLater)
{
    // rpm on BerkeleyDB marks only the start of a transaction: the first
    // refresh may read it mid-way, the follow-up reads where it ended.
    FreshnessMarks marks {seconds{5}, seconds{30}};
    const auto t0 = Clock::time_point {} + seconds{1000};

    marks.mark("a", t0);
    EXPECT_EQ(marks.takeDue(t0 + seconds{5}, ADMIT_ALL), (std::vector<std::string> {"a"}));
    EXPECT_TRUE(marks.takeDue(t0 + seconds{20}, ADMIT_ALL).empty());
    EXPECT_EQ(marks.takeDue(t0 + seconds{35}, ADMIT_ALL), (std::vector<std::string> {"a"}));
    EXPECT_TRUE(marks.takeDue(t0 + seconds{70}, ADMIT_ALL).empty()) << "a follow-up brings no follow-up";
}

TEST(ContainerFreshnessMarksTest, AWriteBeforeTheFollowUpIsServedOnceInItsPlace)
{
    FreshnessMarks marks {seconds{5}, seconds{30}};
    const auto t0 = Clock::time_point {} + seconds{1000};

    marks.mark("a", t0);
    ASSERT_EQ(marks.takeDue(t0 + seconds{5}, ADMIT_ALL).size(), 1u);

    marks.mark("a", t0 + seconds{10});
    EXPECT_EQ(marks.takeDue(t0 + seconds{35}, ADMIT_ALL), (std::vector<std::string> {"a"}));
    EXPECT_TRUE(marks.takeDue(t0 + seconds{40}, ADMIT_ALL).empty()) << "one refresh, not two";
    EXPECT_EQ(marks.takeDue(t0 + seconds{65}, ADMIT_ALL), (std::vector<std::string> {"a"}))
            << "the write brings its own follow-up";
}

TEST(ContainerFreshnessNameListsTest, EachEnabledNameOnce)
{
    const std::vector<FreshnessSource> sources
    {
        {"/etc/passwd", CONTAINER_SOURCE_USERS, false},
        {"/etc/os-release", CONTAINER_SOURCE_OS, false},
        {"/usr/lib/os-release", CONTAINER_SOURCE_OS, false},
        {"/var/lib/dpkg/status", CONTAINER_SOURCE_PACKAGES, false},
        {"/var/lib/dpkg/status.d", CONTAINER_SOURCE_PACKAGES, true},
        {"/var/lib/rpm/rpmdb.sqlite", CONTAINER_SOURCE_PACKAGES, false},
        {"/usr/lib/sysimage/rpm/rpmdb.sqlite", CONTAINER_SOURCE_PACKAGES, false},
    };

    const auto packages = nameFilterLists(sources, CONTAINER_SOURCE_PACKAGES);
    EXPECT_EQ(packages.first, (std::vector<std::string> {"rpmdb.sqlite", "status"}));
    EXPECT_EQ(packages.second, (std::vector<std::string> {"status.d"}));

    const auto os = nameFilterLists(sources, CONTAINER_SOURCE_OS);
    EXPECT_EQ(os.first, (std::vector<std::string> {"os-release"}));
    EXPECT_TRUE(os.second.empty());
}
