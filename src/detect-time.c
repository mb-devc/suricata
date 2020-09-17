/* Copyright (C) 2007-2020 Open Information Security Foundation
 *
 * You can copy, redistribute or modify this Program under the terms of
 * the GNU General Public License version 2 as published by the Free
 * Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 */

/**
 * \file
 *
 * \author Michael
 *
 */

#include "suricata-common.h"
#include "util-byte.h"
#include "util-time.h"

#include "detect.h"
#include "detect-parse.h"
#include "detect-engine-prefilter-common.h"

#include "detect-time.h"

/**
 * \brief Regex for parsing our options
 *
 * Matches an assertion about the time. For example: "< 13.34"
 */
#define PARSE_REGEX  "^\\s*([<>])\\s*([0-9]{0,2}):([0-2]{0,2})\\s*$"

static DetectParseRegex parse_regex;

/* prototypes */
static int DetectTimeMatch (DetectEngineThreadCtx *, Packet *,
        const Signature *, const SigMatchCtx *);
static int DetectTimeSetup (DetectEngineCtx *, Signature *, const char *);
void DetectTimeFree (DetectEngineCtx *, void *);
#ifdef UNITTESTS
void DetectTimeRegisterTests (void);
#endif
static int PrefilterSetupTime(DetectEngineCtx *de_ctx, SigGroupHead *sgh);
static bool PrefilterTimeIsPrefilterable(const Signature *s);

/**
 * \brief Registration function for time: keyword
 */

void DetectTimeRegister(void)
{
    // Don't think this is used for lookup or anything, just logging
    sigmatch_table[DETECT_TIME].name = "time";
    // Description, just metadata, nothing too important
    sigmatch_table[DETECT_TIME].desc = "TODO describe the keyword";
    // about 0 clue what this does, TODO
    sigmatch_table[DETECT_TIME].url = "/rules/header-keywords.html#time";
    // registry - function for matching 
    sigmatch_table[DETECT_TIME].Match = DetectTimeMatch;
    // this is where we get to parse the actual rule(s)
    // TODO - is this called 1x per RULE that has a time: assertion?
    // performance concerns might be more important than initially presumed...
    sigmatch_table[DETECT_TIME].Setup = DetectTimeSetup;
    // pretty simple free function
    sigmatch_table[DETECT_TIME].Free = DetectTimeFree;
#ifdef UNITTESTS
    // need to make sure to make unit tests TODO
    sigmatch_table[DETECT_TIME].RegisterTests = DetectTimeRegisterTests;
#endif
    sigmatch_table[DETECT_TIME].SupportsPrefilter = PrefilterTimeIsPrefilterable;
    sigmatch_table[DETECT_TIME].SetupPrefilter = PrefilterSetupTime;

    DetectSetupParseRegexes(PARSE_REGEX, &parse_regex);
    return;
}

static inline int TimeMatch(const uint16_t const_minutes, const uint8_t mode, const uint16_t day_minutes)
{
    // Rationale: SCLocalTime returns floor(minutes)
    // <= here would include up to a minute of incorrect times.
    if (mode == DETECT_TIME_LT && day_minutes < const_minutes)
        return 1;
    // > here would not include a minute of incorrect times.
    // Furthermore, it should be possible to match on the exact time.
    // The alternative would be to allow for <=, >=, which is still a 
    // potentially viable addition, just not worth it for current testing,
    // especially considering the implications of (x minutes = some value) -
    // would it only match when there is a 0s0ms offset, or when the minute matches?
    // The former is quite unlikely, whereas the latter is functionally identical
    // to the current implementation, but for an - again - fairly unlikely chance.
    // The tradeoff here is API simplicity for potential confusion regarding the implementation.
    else if (mode == DETECT_TIME_GT && day_minutes >= const_minutes)
        return 1;

    return 0;
}

/**
 * \brief This function is used to match TIME rule option on a packet with those passed via time:
 *
 * \param t pointer to thread vars
 * \param det_ctx pointer to the pattern matcher thread
 * \param p pointer to the current packet
 * \param m pointer to the sigmatch that we will cast into DetectTimeData
 *
 * \retval 0 no match
 * \retval 1 match
 */
static int DetectTimeMatch (DetectEngineThreadCtx *det_ctx, Packet *p,
        const Signature *s, const SigMatchCtx *ctx)
{
    // TODO what in the world is a pseudopacket
    if (PKT_IS_PSEUDOPKT(p))
        return 0;

    const DetectTimeData *timed = (const DetectTimeData *)ctx;

    // For now, we can get this information inside of the match function
    // It would be wise to instead get it earlier (when the packet is actually
    // received by the engine)
    struct timeval tval;

    TimeGet(&tval);
    struct tm local_tm;
    // Caching, fewer locks, internal method.
    SCLocalTime(tval.tv_sec, &local_tm);
    SCLogError(SC_ERR_PCRE_MATCH, "tried to match");
    uint16_t day_minutes = local_tm.tm_min + (local_tm.tm_hour * 60);

    return TimeMatch(timed->minutes, timed->mode, day_minutes);
}

/**
 * \brief This function is used to parse time options passed via time: keyword
 *
 * \param timestr Pointer to the user provided time options
 *
 * \retval timed pointer to DetectTimeData on success
 * \retval NULL on failure
 */

static DetectTimeData *DetectTimeParse (const char *timestr)
{
    DetectTimeData *timed = NULL;
    char *arg_operator = NULL;
    char *arg_hours = NULL;
    char *arg_minutes = NULL;
    int ret = 0, res = 0;
    int ov[MAX_SUBSTRINGS];

    ret = DetectParsePcreExec(&parse_regex, timestr, 0, 0, ov, MAX_SUBSTRINGS);
    if (ret != 4) {
        SCLogError(SC_ERR_PCRE_MATCH, "parse error, ret %" PRId32 "", ret);
        goto error;
    }
    const char *str_ptr;

    res = pcre_get_substring((char *) timestr, ov, MAX_SUBSTRINGS, 1, &str_ptr);
    if (res < 0) {
        SCLogError(SC_ERR_PCRE_GET_SUBSTRING, "pcre_get_substring failed");
        goto error;
    }
    arg_operator = (char *) str_ptr;
    SCLogDebug("Argument - Operator: \"%s\"", arg_operator);

    res = pcre_get_substring((char *) timestr, ov, MAX_SUBSTRINGS, 2, &str_ptr);
    if (res < 0) {
        SCLogError(SC_ERR_PCRE_GET_SUBSTRING, "pcre_get_substring failed");
        goto error;
    }
    arg_hours = (char *) str_ptr;
    SCLogDebug("Argument - Hours: \"%s\"", arg_hours);

    res = pcre_get_substring((char *) timestr, ov, MAX_SUBSTRINGS, 3, &str_ptr);
    if (res < 0) {
        SCLogError(SC_ERR_PCRE_GET_SUBSTRING, "pcre_get_substring failed");
        goto error;
    }
    arg_minutes = (char *) str_ptr;
    SCLogDebug("Argument - Minutes: \"%s\"", arg_minutes);

    timed = SCMalloc(sizeof (DetectTimeData));
    if (unlikely(timed == NULL))
        goto error;

    timed->minutes = 0;
    timed->mode = 0;

    if (arg_operator[0] == '>') timed->mode = DETECT_TIME_GT;
    if (arg_operator[0] == '<') timed->mode = DETECT_TIME_LT;

    // Do I need a nullcheck for arg_hours, arg_minutes?
    // Reference code seemed to imply this, but manpage doesn't
    // give any mention of null returns.
    uint16_t hours = 0;
    uint16_t minutes = 0;
    if (StringParseUint16(&hours, 10, 0, (const char *)arg_hours) < 0) {
        SCLogError(SC_ERR_INVALID_SIGNATURE, "Invalid first arg:"
                   " \"%s\"", arg_hours);
        goto error;
    }
    if (StringParseUint16(&minutes, 10, 0, (const char *)arg_minutes) < 0) {
        SCLogError(SC_ERR_INVALID_SIGNATURE, "Invalid first arg:"
                   " \"%s\"", arg_minutes);
        goto error;
    }
    timed->minutes = (hours * 60) + minutes;
    SCFree(arg_operator);
    SCFree(arg_hours);
    SCFree(arg_minutes);
    return timed;

error:
    if (timed)
        SCFree(timed);
    if (arg_operator)
        SCFree(arg_operator);
    if (arg_hours)
        SCFree(arg_hours);
    if (arg_minutes)
        SCFree(arg_minutes);
    return NULL;
}

/**
 * \brief this function is used to atimed the parsed time data into the current signature
 *
 * \param de_ctx pointer to the Detection Engine Context
 * \param s pointer to the Current Signature
 * \param timestr pointer to the user provided time options
 *
 * \retval 0 on Success
 * \retval -1 on Failure
 */
static int DetectTimeSetup (DetectEngineCtx *de_ctx, Signature *s, const char *timestr)
{
    DetectTimeData *timed = DetectTimeParse(timestr);
    if (timed == NULL)
        return -1;

    SigMatch *sm = SigMatchAlloc();
    if (sm == NULL) {
        DetectTimeFree(de_ctx, timed);
        return -1;
    }

    sm->type = DETECT_TIME;
    sm->ctx = (SigMatchCtx *)timed;

    SigMatchAppendSMToList(s, sm, DETECT_SM_LIST_MATCH);
    s->flags |= SIG_FLAG_REQUIRE_PACKET;

    return 0;
}

/**
 * \brief this function will free memory associated with DetectTimeData
 *
 * \param ptr pointer to DetectTimeData
 */
void DetectTimeFree(DetectEngineCtx *de_ctx, void *ptr)
{
    DetectTimeData *timed = (DetectTimeData *)ptr;
    SCFree(timed);
}

/* prefilter code */

static void
PrefilterPacketTimeMatch(DetectEngineThreadCtx *det_ctx, Packet *p, const void *pectx)
{
    if (PKT_IS_PSEUDOPKT(p)) {
        SCReturn;
    }

    uint8_t ptime;
/* TODO update */
    if (PKT_IS_IPV4(p)) {
        ptime = IPV4_GET_IPTTL(p);
    } else if (PKT_IS_IPV6(p)) {
        ptime = IPV6_GET_HLIM(p);
    } else {
        SCLogDebug("Packet is of not IPv4 or IPv6");
        return;
    }

    /* during setup Suricata will automatically see if there is another
     * check that can be added: alproto, sport or dport */
    const PrefilterPacketHeaderCtx *ctx = pectx;
    if (PrefilterPacketHeaderExtraMatch(ctx, p) == FALSE)
        return;
}

// Not sure what these do, TODO
static void
PrefilterPacketTimeSet(PrefilterPacketHeaderValue *v, void *smctx)
{
    const DetectTimeData *a = smctx;
    v->u8[0] = a->mode;
    v->u16[0] = a->minutes;
}

static bool
PrefilterPacketTimeCompare(PrefilterPacketHeaderValue v, void *smctx)
{
    const DetectTimeData *a = smctx;
    if (v.u8[0] == a->mode &&
        v.u16[0] == a->minutes)
        return TRUE;
    return FALSE;
}

static int PrefilterSetupTime(DetectEngineCtx *de_ctx, SigGroupHead *sgh)
{
    return PrefilterSetupPacketHeader(de_ctx, sgh, DETECT_TIME,
            PrefilterPacketTimeSet,
            PrefilterPacketTimeCompare,
            PrefilterPacketTimeMatch);
}

static bool PrefilterTimeIsPrefilterable(const Signature *s)
{
    const SigMatch *sm;
    for (sm = s->init_data->smlists[DETECT_SM_LIST_MATCH] ; sm != NULL; sm = sm->next) {
        switch (sm->type) {
            case DETECT_TIME:
                return TRUE;
        }
    }
    return FALSE;
}

#ifdef UNITTESTS
#include "tests/detect-time.c"
#endif

