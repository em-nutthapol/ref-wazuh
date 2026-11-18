// SPDX-License-Identifier: AGPL-3.0-or-later
#include <benchmark/benchmark.h>

#include <cstdint>
#include <exception>
#include <string>
#include <utility>
#include <vector>

#include <base/json.hpp>
#include <hlp/hlp.hpp>
#include <hlp/parser.hpp>

// Cost of the JSON-building stage of the kv and xml parsers against the number of members written into one object.
// Every timed iteration runs the three stages (hlp::parser::run) on a fresh, empty event.

namespace
{

const std::string TARGET = "/out";

/** @brief Post-conditions on the parsed event: each JSON pointer must have the given size (members or elements). */
using SizeChecks = std::vector<std::pair<std::string, size_t>>;

hlp::Params kvParams()
{
    return hlp::Params {"kv", TARGET, {}, {"=", " ", "'", "\\"}};
}

hlp::Params xmlParams(bool windows = false)
{
    hlp::Params params {"xml", TARGET, {""}, {}};
    if (windows)
    {
        params.options = {"windows"};
    }
    return params;
}

bool checkSizes(const json::Json& probe, const SizeChecks& checks)
{
    for (const auto& [pointer, expected] : checks)
    {
        try
        {
            if (probe.size(pointer) != expected)
            {
                return false;
            }
        }
        catch (const std::exception&)
        {
            return false;
        }
    }
    return true;
}

// Parses text once to validate it, then times hlp::parser::run on a fresh event per iteration.
void runParser(benchmark::State& state,
               const hlp::parser::Parser& parser,
               const std::string& text,
               const SizeChecks& checks)
{
    // input_bytes is the size of the input text.
    state.counters["input_bytes"] = static_cast<double>(text.size());

    // Untimed guard: runs the whole parse once, so the wall clock of single-iteration sizes is about twice the
    // reported time.
    {
        json::Json probe;
        const auto err = hlp::parser::run(parser, text, probe);
        if (err.has_value())
        {
            state.SkipWithError("parse failed");
            return;
        }
        if (!checkSizes(probe, checks))
        {
            state.SkipWithError("the parser did not write the expected members");
            return;
        }
    }

    for (auto _ : state)
    {
        json::Json event;
        auto err = hlp::parser::run(parser, text, event);
        benchmark::DoNotOptimize(err);
        benchmark::DoNotOptimize(event);
    }
}

/** @brief kv text "<prefix>k0=v <prefix>k1=v ...". */
std::string kvText(int64_t n, const std::string& prefix)
{
    std::string text;
    for (int64_t i = 0; i < n; ++i)
    {
        if (i > 0)
        {
            text += ' ';
        }
        text += prefix + "k" + std::to_string(i) + "=v";
    }
    return text;
}

std::string xmlSiblings(int64_t n)
{
    std::string text = "<r>";
    for (int64_t i = 0; i < n; ++i)
    {
        const auto name = "k" + std::to_string(i);
        text += "<" + name + ">v</" + name + ">";
    }
    text += "</r>";
    return text;
}

std::string xmlAttributes(int64_t n)
{
    std::string text = "<r";
    for (int64_t i = 0; i < n; ++i)
    {
        text += " k" + std::to_string(i) + "=\"v\"";
    }
    text += " />";
    return text;
}

constexpr int64_t WIDE_SIBLINGS = 64;

/** @brief WIDE_SIBLINGS children "s0" ... "s63" of "r", each with n / WIDE_SIBLINGS attributes. */
std::string xmlAttributesWide(int64_t n)
{
    const int64_t perNode = n / WIDE_SIBLINGS;
    std::string text = "<r>";
    for (int64_t s = 0; s < WIDE_SIBLINGS; ++s)
    {
        text += "<s" + std::to_string(s);
        for (int64_t i = 0; i < perNode; ++i)
        {
            text += " k" + std::to_string(i) + "=\"v\"";
        }
        text += " />";
    }
    text += "</r>";
    return text;
}

std::string xmlWindowsData(int64_t n)
{
    std::string text = "<EventData>";
    for (int64_t i = 0; i < n; ++i)
    {
        text += "<Data Name=\"k" + std::to_string(i) + "\">v</Data>";
    }
    text += "</EventData>";
    return text;
}

std::string xmlRepeatedSibling(int64_t n)
{
    std::string text = "<r>";
    for (int64_t i = 0; i < n; ++i)
    {
        text += "<a>v</a>";
    }
    text += "</r>";
    return text;
}

/** @brief kv text "k=<value>", where the value is L bytes before unescaping. */
std::string kvDenseEscapes(int64_t bytes)
{
    return "k=" + std::string(static_cast<size_t>(bytes), '\\');
}

/** @brief L bytes of 'v' with two escaped escapes replacing bytes at a third and two thirds of the value. */
std::string kvSparseEscapes(int64_t bytes)
{
    const auto length = static_cast<size_t>(bytes);
    std::string value(length, 'v');
    value[length / 3] = '\\';
    value[length / 3 + 1] = '\\';
    value[2 * length / 3] = '\\';
    value[2 * length / 3 + 1] = '\\';
    return "k=" + value;
}

std::string kvPlainValue(int64_t bytes)
{
    return "k=" + std::string(static_cast<size_t>(bytes), 'v');
}

/** @brief 64 children of "r" whose names are nameLength bytes long: the ancestor path grows, the writes do not. */
std::string xmlNameLength(int64_t nameLength)
{
    constexpr int64_t CHILDREN = 64;
    const auto length = static_cast<size_t>(nameLength);
    std::string text = "<r>";
    for (int64_t i = 0; i < CHILDREN; ++i)
    {
        // An XML element name cannot start with a digit, so the index goes at the end.
        const auto index = std::to_string(i);
        const auto fill = length > index.size() + 1 ? length - index.size() - 1 : 1;
        const auto name = "n" + std::string(fill, 'x') + index;
        text += "<" + name + ">v</" + name + ">";
    }
    text += "</r>";
    return text;
}

/** @brief A chain of depth elements, "v" at the bottom. */
std::string xmlDepth(int64_t depth)
{
    std::string open;
    std::string close;
    for (int64_t i = 0; i < depth; ++i)
    {
        const auto name = "n" + std::to_string(i);
        open += "<" + name + ">";
        close = "</" + name + ">" + close;
    }
    return open + "v" + close;
}

/**
 * @brief A chain of depth levels, each one holding a repeated sibling of one leaf before nesting further.
 *
 * The subtree the array promotion copies is one leaf at every level, so this case sweeps the depth with the
 * promotion cost held constant. The sweep over the size of the copied subtree is BM_ParseXml_RepeatedSiblingBytes and
 * BM_ParseXml_RepeatedSiblingNodes.
 */
std::string xmlNestedRepeatedSibling(int64_t depth)
{
    std::string open;
    std::string close;
    for (int64_t i = 0; i < depth; ++i)
    {
        const auto name = "n" + std::to_string(i);
        open += "<" + name + "><a>v</a><a>v</a>";
        close = "</" + name + ">" + close;
    }
    return open + close;
}

/** @brief k leaf elements "k0".."k<n>", the payload the two cases below put under a chain or under a sibling. */
std::string xmlLeaves(int64_t k)
{
    std::string leaves;
    for (int64_t i = 0; i < k; ++i)
    {
        const auto name = "k" + std::to_string(i);
        leaves += "<" + name + ">v</" + name + ">";
    }
    return leaves;
}

/**
 * @brief A chain of depth levels of "a" with k leaf elements at the bottom, optionally repeating "a" at each level.
 *
 * Each level adds a few bytes, so the input stays about the size of the payload while the depth varies: the sweep
 * is over the depth alone. Every write under the chain parses the whole ancestor path again, so the cost of the
 * payload grows with the depth above it while the bytes parsed do not. With repeated set, a second "a" at every
 * level turns its parent into an array, and what the promotion copies is the whole chain below it: the two costs
 * compound, which is the worst case for both.
 */
std::string xmlDeepBulk(int64_t depth, int64_t k, bool repeated)
{
    std::string text = xmlLeaves(k);
    for (int64_t i = 0; i < depth; ++i)
    {
        text = "<a>" + text + "</a>" + (repeated ? "<a>v</a>" : "");
    }
    return "<r>" + text + "</r>";
}

/**
 * @brief One "a" under "r" holding bytes of text, followed by a second "a" of one leaf when repeated.
 *
 * The second sibling turns "a" into an array, which copies the subtree already written for the first one. The depth
 * and the number of elements are fixed, so a sweep over bytes moves only the bytes that copy carries; the plain case
 * writes the same payload without the second sibling, so the difference between the two is the copy. Paired with
 * xmlSiblingSubtreeNodes, which holds the bytes near fixed and sweeps the number of elements instead: the two
 * together say which of the size of a subtree and its number of nodes the copy is paid on.
 */
std::string xmlSiblingSubtreeBytes(int64_t bytes, bool repeated)
{
    const std::string text(static_cast<size_t>(bytes), 'v');
    return "<r><a><t>" + text + "</t></a>" + (repeated ? "<a>v</a>" : "") + "</r>";
}

/** @brief The same shape with k leaf elements in place of the text, so the sweep is over the nodes copied. */
std::string xmlSiblingSubtreeNodes(int64_t k, bool repeated)
{
    return "<r><a>" + xmlLeaves(k) + "</a>" + (repeated ? "<a>v</a>" : "") + "</r>";
}

void BM_ParseKv_Flat(benchmark::State& state)
{
    const auto n = static_cast<size_t>(state.range(0));
    const auto parser = hlp::parsers::getKVParser(kvParams());
    runParser(state, parser, kvText(state.range(0), ""), {{TARGET, n}});
}

void BM_ParseKv_Dotted(benchmark::State& state)
{
    const auto n = static_cast<size_t>(state.range(0));
    const auto parser = hlp::parsers::getKVParser(kvParams());
    runParser(state, parser, kvText(state.range(0), "a."), {{TARGET + "/a", n}});
}

void BM_ParseXml_Siblings(benchmark::State& state)
{
    const auto n = static_cast<size_t>(state.range(0));
    const auto parser = hlp::parsers::getXMLParser(xmlParams());
    runParser(state, parser, xmlSiblings(state.range(0)), {{TARGET + "/r", n}});
}

void BM_ParseXml_Attributes(benchmark::State& state)
{
    const auto n = static_cast<size_t>(state.range(0));
    const auto parser = hlp::parsers::getXMLParser(xmlParams());
    runParser(state, parser, xmlAttributes(state.range(0)), {{TARGET + "/r", n}});
}

void BM_ParseXml_AttributesWide(benchmark::State& state)
{
    const auto n = static_cast<size_t>(state.range(0));
    const auto parser = hlp::parsers::getXMLParser(xmlParams());
    runParser(state,
              parser,
              xmlAttributesWide(state.range(0)),
              {{TARGET + "/r", static_cast<size_t>(WIDE_SIBLINGS)}, {TARGET + "/r/s0", n / WIDE_SIBLINGS}});
}

void BM_ParseXml_WindowsData(benchmark::State& state)
{
    const auto n = static_cast<size_t>(state.range(0));
    const auto parser = hlp::parsers::getXMLParser(xmlParams(true));
    runParser(state, parser, xmlWindowsData(state.range(0)), {{TARGET + "/EventData", n}});
}

void BM_ParseXml_RepeatedSibling(benchmark::State& state)
{
    const auto n = static_cast<size_t>(state.range(0));
    const auto parser = hlp::parsers::getXMLParser(xmlParams());
    runParser(state, parser, xmlRepeatedSibling(state.range(0)), {{TARGET + "/r/a", n}});
}

// Cost of unescaping against the number of bytes of the value. The post-conditions are the unescaped length
// of the value, so a run that does not reach unescape (the kv parser only sets its escape flag when an escape
// precedes the quote, the escape, the separator or the delimiter) fails instead of silently measuring nothing.
void BM_ParseKv_Escapes(benchmark::State& state)
{
    const auto bytes = static_cast<size_t>(state.range(0));
    const auto parser = hlp::parsers::getKVParser(kvParams());
    runParser(state, parser, kvDenseEscapes(state.range(0)), {{TARGET + "/k", bytes / 2}});
}

void BM_ParseKv_SparseEscape(benchmark::State& state)
{
    const auto bytes = static_cast<size_t>(state.range(0));
    const auto parser = hlp::parsers::getKVParser(kvParams());
    runParser(state, parser, kvSparseEscapes(state.range(0)), {{TARGET + "/k", bytes - 2}});
}

void BM_ParseKv_PlainValue(benchmark::State& state)
{
    const auto bytes = static_cast<size_t>(state.range(0));
    const auto parser = hlp::parsers::getKVParser(kvParams());
    runParser(state, parser, kvPlainValue(state.range(0)), {{TARGET + "/k", bytes}});
}

void BM_ParseXml_NameLength(benchmark::State& state)
{
    const auto parser = hlp::parsers::getXMLParser(xmlParams());
    runParser(state, parser, xmlNameLength(state.range(0)), {{TARGET + "/r", 64}});
}

void BM_ParseXml_Depth(benchmark::State& state)
{
    const auto parser = hlp::parsers::getXMLParser(xmlParams());
    runParser(state, parser, xmlDepth(state.range(0)), {{TARGET + "/n0", 1}});
}

void BM_ParseXml_NestedRepeatedSibling(benchmark::State& state)
{
    const auto parser = hlp::parsers::getXMLParser(xmlParams());
    runParser(state, parser, xmlNestedRepeatedSibling(state.range(0)), {{TARGET + "/n0/a", 2}});
}

// The payload of the two cases below: large enough that the cost of the variable under sweep dominates the fixed
// cost of the parse, small enough that every point of the sweep stays in the millisecond range.
constexpr int64_t XML_BULK_LEAVES = 4096;

void BM_ParseXml_DeepBulk(benchmark::State& state)
{
    const auto parser = hlp::parsers::getXMLParser(xmlParams());
    runParser(state, parser, xmlDeepBulk(state.range(0), XML_BULK_LEAVES, false), {{TARGET + "/r", 1}});
}

void BM_ParseXml_DeepBulkRepeated(benchmark::State& state)
{
    const auto parser = hlp::parsers::getXMLParser(xmlParams());
    runParser(state, parser, xmlDeepBulk(state.range(0), XML_BULK_LEAVES, true), {{TARGET + "/r/a", 2}});
}

void BM_ParseXml_RepeatedSiblingBytes(benchmark::State& state)
{
    const auto parser = hlp::parsers::getXMLParser(xmlParams());
    runParser(state, parser, xmlSiblingSubtreeBytes(state.range(0), true), {{TARGET + "/r/a", 2}});
}

void BM_ParseXml_PlainSiblingBytes(benchmark::State& state)
{
    const auto parser = hlp::parsers::getXMLParser(xmlParams());
    runParser(state, parser, xmlSiblingSubtreeBytes(state.range(0), false), {{TARGET + "/r/a", 1}});
}

void BM_ParseXml_RepeatedSiblingNodes(benchmark::State& state)
{
    const auto parser = hlp::parsers::getXMLParser(xmlParams());
    runParser(state, parser, xmlSiblingSubtreeNodes(state.range(0), true), {{TARGET + "/r/a", 2}});
}

void BM_ParseXml_PlainSiblingNodes(benchmark::State& state)
{
    const auto n = static_cast<size_t>(state.range(0));
    const auto parser = hlp::parsers::getXMLParser(xmlParams());
    runParser(state, parser, xmlSiblingSubtreeNodes(state.range(0), false), {{TARGET + "/r/a", n}});
}

} // namespace

// =============================================================================
// Registrations: a range sweep per benchmark, plus two small sizes for the per-event cost.
// =============================================================================

#define REGISTER_SCALING_BENCH(name)                                                                                   \
    BENCHMARK(name)->RangeMultiplier(4)->Range(16, 65536)->Unit(benchmark::kMicrosecond)

// Small objects: per-event cost with few members.
BENCHMARK(BM_ParseKv_Flat)->Arg(8)->Arg(32)->Unit(benchmark::kMicrosecond);
BENCHMARK(BM_ParseKv_Dotted)->Arg(8)->Arg(32)->Unit(benchmark::kMicrosecond);
BENCHMARK(BM_ParseXml_Siblings)->Arg(8)->Arg(32)->Unit(benchmark::kMicrosecond);
BENCHMARK(BM_ParseXml_Attributes)->Arg(8)->Arg(32)->Unit(benchmark::kMicrosecond);
BENCHMARK(BM_ParseXml_WindowsData)->Arg(8)->Arg(32)->Unit(benchmark::kMicrosecond);
BENCHMARK(BM_ParseXml_RepeatedSibling)->Arg(8)->Arg(32)->Unit(benchmark::kMicrosecond);

REGISTER_SCALING_BENCH(BM_ParseKv_Flat);
REGISTER_SCALING_BENCH(BM_ParseKv_Dotted);
REGISTER_SCALING_BENCH(BM_ParseXml_Siblings);
REGISTER_SCALING_BENCH(BM_ParseXml_Attributes);
// Starts at 64: one attribute per sibling at least.
BENCHMARK(BM_ParseXml_AttributesWide)->RangeMultiplier(4)->Range(64, 65536)->Unit(benchmark::kMicrosecond);
REGISTER_SCALING_BENCH(BM_ParseXml_WindowsData);
// Repeated siblings are appended to their array, so the memory of this case grows with N: the peak RSS of the process
// (about 11 MiB with small sizes) is about 18 MiB at 16 384 and about 56 MiB at 65 536 in a Release build.
REGISTER_SCALING_BENCH(BM_ParseXml_RepeatedSibling);

// Unescaping: swept by bytes of the value, not by number of members.
#define REGISTER_VALUE_BYTES_BENCH(name)                                                                               \
    BENCHMARK(name)->RangeMultiplier(4)->Range(1024, 1048576)->Unit(benchmark::kMicrosecond)

REGISTER_VALUE_BYTES_BENCH(BM_ParseKv_Escapes);
REGISTER_VALUE_BYTES_BENCH(BM_ParseKv_SparseEscape);
REGISTER_VALUE_BYTES_BENCH(BM_ParseKv_PlainValue);

// The two remaining costs of the xml parser: the ancestor path, which every write parses again, and the
// subtree that a repeated sibling copies when its parent turns into an array.
BENCHMARK(BM_ParseXml_NameLength)->RangeMultiplier(4)->Range(4, 4096)->Unit(benchmark::kMicrosecond);
BENCHMARK(BM_ParseXml_Depth)->RangeMultiplier(2)->Range(2, 128)->Unit(benchmark::kMicrosecond);
BENCHMARK(BM_ParseXml_NestedRepeatedSibling)->RangeMultiplier(2)->Range(2, 128)->Unit(benchmark::kMicrosecond);

// The same two costs with one variable at a time, which is what the measurements compare.
// Depth, at a payload that does not change with it: 4096 leaves under a chain of D levels. The nesting cap is
// json::Json::MAX_DEPTH (256) counting every element, so the chain stops well below it.
// The last point is the deepest chain the nesting cap admits: the leaves sit at depth + 2, and an element deeper
// than json::Json::MAX_DEPTH (256) stops the conversion.
BENCHMARK(BM_ParseXml_DeepBulk)->RangeMultiplier(2)->Range(1, 128)->Arg(254)->Unit(benchmark::kMicrosecond);
// The same chain with the promotion happening at every level: the ancestor path and the copied subtree compound.
BENCHMARK(BM_ParseXml_DeepBulkRepeated)->RangeMultiplier(2)->Range(1, 128)->Arg(254)->Unit(benchmark::kMicrosecond);
// What a repeated sibling copies, at a fixed depth, swept twice: over the bytes of the subtree with its number of
// elements fixed, and over its number of elements with its bytes near fixed. The plain case writes the same payload
// without the second sibling, so the difference between the two is the cost of the copy.
BENCHMARK(BM_ParseXml_RepeatedSiblingBytes)->RangeMultiplier(4)->Range(256, 1048576)->Unit(benchmark::kMicrosecond);
BENCHMARK(BM_ParseXml_PlainSiblingBytes)->RangeMultiplier(4)->Range(256, 1048576)->Unit(benchmark::kMicrosecond);
BENCHMARK(BM_ParseXml_RepeatedSiblingNodes)->RangeMultiplier(4)->Range(64, 16384)->Unit(benchmark::kMicrosecond);
BENCHMARK(BM_ParseXml_PlainSiblingNodes)->RangeMultiplier(4)->Range(64, 16384)->Unit(benchmark::kMicrosecond);
