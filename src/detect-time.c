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
 * \author XXX
 *
 */

#include "suricata-common.h"
#include "util-byte.h"

#include "detect.h"
#include "detect-parse.h"
#include "detect-engine-prefilter-common.h"

#include "detect-time.h"

/**
 * \brief Regex for parsing our options
 */
#define PARSE_REGEX  "^\\s*([0-9]*)?\\s*([<>=-]+)?\\s*([0-9]+)?\\s*$"

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
    sigmatch_table[DETECT_TIME].name = "time";
    sigmatch_table[DETECT_TIME].desc = "TODO describe the keyword";
    sigmatch_table[DETECT_TIME].url = "/rules/header-keywords.html#time";
    sigmatch_table[DETECT_TIME].Match = DetectTimeMatch;
    sigmatch_table[DETECT_TIME].Setup = DetectTimeSetup;
    sigmatch_table[DETECT_TIME].Free = DetectTimeFree;
#ifdef UNITTESTS
    sigmatch_table[DETECT_TIME].RegisterTests = DetectTimeRegisterTests;
#endif
    sigmatch_table[DETECT_TIME].SupportsPrefilter = PrefilterTimeIsPrefilterable;
    sigmatch_table[DETECT_TIME].SetupPrefilter = PrefilterSetupTime;

    DetectSetupParseRegexes(PARSE_REGEX, &parse_regex);
    return;
}

static inline int TimeMatch(const uint8_t parg, const uint8_t mode,
        const uint8_t darg1, const uint8_t darg2)
{
    if (mode == DETECT_TIME_EQ && parg == darg1)
        return 1;
    else if (mode == DETECT_TIME_LT && parg < darg1)
        return 1;
    else if (mode == DETECT_TIME_GT && parg > darg1)
        return 1;
    else if (mode == DETECT_TIME_RA && (parg > darg1 && parg < darg2))
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

    if (PKT_IS_PSEUDOPKT(p))
        return 0;

    /* TODO replace this */
    uint8_t ptime;
    if (PKT_IS_IPV4(p)) {
        ptime = IPV4_GET_IPTTL(p);
    } else if (PKT_IS_IPV6(p)) {
        ptime = IPV6_GET_HLIM(p);
    } else {
        SCLogDebug("Packet is of not IPv4 or IPv6");
        return 0;
    }

    const DetectTimeData *timed = (const DetectTimeData *)ctx;
    return TimeMatch(ptime, timed->mode, timed->arg1, timed->arg2);
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
    char *arg1 = NULL;
    char *arg2 = NULL;
    char *arg3 = NULL;
    int ret = 0, res = 0;
    int ov[MAX_SUBSTRINGS];

    ret = DetectParsePcreExec(&parse_regex, timestr, 0, 0, ov, MAX_SUBSTRINGS);
    if (ret < 2 || ret > 4) {
        SCLogError(SC_ERR_PCRE_MATCH, "parse error, ret %" PRId32 "", ret);
        goto error;
    }
    const char *str_ptr;

    res = pcre_get_substring((char *) timestr, ov, MAX_SUBSTRINGS, 1, &str_ptr);
    if (res < 0) {
        SCLogError(SC_ERR_PCRE_GET_SUBSTRING, "pcre_get_substring failed");
        goto error;
    }
    arg1 = (char *) str_ptr;
    SCLogDebug("Arg1 \"%s\"", arg1);

    if (ret >= 3) {
        res = pcre_get_substring((char *) timestr, ov, MAX_SUBSTRINGS, 2, &str_ptr);
        if (res < 0) {
            SCLogError(SC_ERR_PCRE_GET_SUBSTRING, "pcre_get_substring failed");
            goto error;
        }
        arg2 = (char *) str_ptr;
        SCLogDebug("Arg2 \"%s\"", arg2);

        if (ret >= 4) {
            res = pcre_get_substring((char *) timestr, ov, MAX_SUBSTRINGS, 3, &str_ptr);
            if (res < 0) {
                SCLogError(SC_ERR_PCRE_GET_SUBSTRING, "pcre_get_substring failed");
                goto error;
            }
            arg3 = (char *) str_ptr;
            SCLogDebug("Arg3 \"%s\"", arg3);
        }
    }

    timed = SCMalloc(sizeof (DetectTimeData));
    if (unlikely(timed == NULL))
        goto error;
    timed->arg1 = 0;
    timed->arg2 = 0;

    if (arg2 != NULL) {
        /*set the values*/
        switch(arg2[0]) {
            case '<':
                if (arg3 == NULL)
                    goto error;

                timed->mode = DETECT_TIME_LT;
                if (StringParseUint8(&timed->arg1, 10, 0, (const char *)arg3) < 0) {
                    SCLogError(SC_ERR_INVALID_SIGNATURE, "Invalid first arg:"
                               " \"%s\"", arg3);
                    goto error;
                }
                SCLogDebug("time is %"PRIu8"",timed->arg1);
                if (strlen(arg1) > 0)
                    goto error;

                break;
            case '>':
                if (arg3 == NULL)
                    goto error;

                timed->mode = DETECT_TIME_GT;
                if (StringParseUint8(&timed->arg1, 10, 0, (const char *)arg3) < 0) {
                    SCLogError(SC_ERR_INVALID_SIGNATURE, "Invalid first arg:"
                               " \"%s\"", arg3);
                    goto error;
                }
                SCLogDebug("time is %"PRIu8"",timed->arg1);
                if (strlen(arg1) > 0)
                    goto error;

                break;
            case '-':
                if (arg1 == NULL || strlen(arg1)== 0)
                    goto error;
                if (arg3 == NULL || strlen(arg3)== 0)
                    goto error;

                timed->mode = DETECT_TIME_RA;
                if (StringParseUint8(&timed->arg1, 10, 0, (const char *)arg1) < 0) {
                    SCLogError(SC_ERR_INVALID_SIGNATURE, "Invalid first arg:"
                               " \"%s\"", arg1);
                    goto error;
                }
                if (StringParseUint8(&timed->arg2, 10, 0, (const char *)arg3) < 0) {
                    SCLogError(SC_ERR_INVALID_SIGNATURE, "Invalid second arg:"
                               " \"%s\"", arg3);
                    goto error;
                }
                SCLogDebug("time is %"PRIu8" to %"PRIu8"",timed->arg1, timed->arg2);
                if (timed->arg1 >= timed->arg2) {
                    SCLogError(SC_ERR_INVALID_SIGNATURE, "Invalid time range. ");
                    goto error;
                }
                break;
            default:
                timed->mode = DETECT_TIME_EQ;

                if ((arg2 != NULL && strlen(arg2) > 0) ||
                    (arg3 != NULL && strlen(arg3) > 0) ||
                    (arg1 == NULL ||strlen(arg1) == 0))
                    goto error;

                if (StringParseUint8(&timed->arg1, 10, 0, (const char *)arg1) < 0) {
                    SCLogError(SC_ERR_INVALID_SIGNATURE, "Invalid first arg:"
                               " \"%s\"", arg1);
                    goto error;
                }
                break;
        }
    } else {
        timed->mode = DETECT_TIME_EQ;

        if ((arg3 != NULL && strlen(arg3) > 0) ||
            (arg1 == NULL ||strlen(arg1) == 0))
            goto error;

        if (StringParseUint8(&timed->arg1, 10, 0, (const char *)arg1) < 0) {
            SCLogError(SC_ERR_INVALID_SIGNATURE, "Invalid first arg:"
                       " \"%s\"", arg1);
            goto error;
        }
    }

    SCFree(arg1);
    SCFree(arg2);
    SCFree(arg3);
    return timed;

error:
    if (timed)
        SCFree(timed);
    if (arg1)
        SCFree(arg1);
    if (arg2)
        SCFree(arg2);
    if (arg3)
        SCFree(arg3);
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

    /* if we match, add all the sigs that use this prefilter. This means
     * that these will be inspected further */
    if (TimeMatch(ptime, ctx->v1.u8[0], ctx->v1.u8[1], ctx->v1.u8[2]))
    {
        SCLogDebug("packet matches time/hl %u", ptime);
        PrefilterAddSids(&det_ctx->pmq, ctx->sigs_array, ctx->sigs_cnt);
    }
}

static void
PrefilterPacketTimeSet(PrefilterPacketHeaderValue *v, void *smctx)
{
    const DetectTimeData *a = smctx;
    v->u8[0] = a->mode;
    v->u8[1] = a->arg1;
    v->u8[2] = a->arg2;
}

static bool
PrefilterPacketTimeCompare(PrefilterPacketHeaderValue v, void *smctx)
{
    const DetectTimeData *a = smctx;
    if (v.u8[0] == a->mode &&
        v.u8[1] == a->arg1 &&
        v.u8[2] == a->arg2)
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

