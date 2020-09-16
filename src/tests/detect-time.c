/* Copyright (C) 2007-2018 Open Information Security Foundation
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

#include "../suricata-common.h"

#include "../detect.h"
#include "../detect-parse.h"
#include "../detect-engine-prefilter-common.h"

#include "../detect-time.h"

#include "../util-unittest.h"

/**
 * \test DetectTimeParseTest01 is a test for setting up an valid time value.
 */

static int DetectTimeParseTest01 (void)
{
    DetectTimeData *timed = DetectTimeParse("10");

    FAIL_IF_NULL(timed);
    FAIL_IF_NOT(timed->arg1 == 10);
    FAIL_IF_NOT(timed->mode == DETECT_TIME_EQ);

    DetectTimeFree(NULL, timed);

    PASS;
}

/**
 * \test DetectTimeParseTest02 is a test for setting up an valid time value with
 *       "<" operator.
 */

static int DetectTimeParseTest02 (void)
{
    DetectTimeData *timed = DetectTimeParse("<10");

    FAIL_IF_NULL(timed);
    FAIL_IF_NOT(timed->arg1 == 10);
    FAIL_IF_NOT(timed->mode == DETECT_TIME_LT);

    DetectTimeFree(NULL, timed);

    PASS;
}

/**
 * \test DetectTimeParseTest03 is a test for setting up an valid time values with
 *       "-" operator.
 */

static int DetectTimeParseTest03 (void)
{
    DetectTimeData *timed = DetectTimeParse("1-2");

    FAIL_IF_NULL(timed);
    FAIL_IF_NOT(timed->arg1 == 1);
    FAIL_IF_NOT(timed->mode == DETECT_TIME_RA);

    DetectTimeFree(NULL, timed);

    PASS;
}

/**
 * \test DetectTimeParseTest04 is a test for setting up an valid time value with
 *       ">" operator and include spaces arround the given values.
 */

static int DetectTimeParseTest04 (void)
{
    DetectTimeData *timed = DetectTimeParse(" > 10 ");

    FAIL_IF_NULL(timed);
    FAIL_IF_NOT(timed->arg1 == 10);
    FAIL_IF_NOT(timed->mode == DETECT_TIME_GT);

    DetectTimeFree(NULL, timed);

    PASS;
}

/**
 * \test DetectTimeParseTest05 is a test for setting up an valid time values with
 *       "-" operator and include spaces arround the given values.
 */

static int DetectTimeParseTest05 (void)
{
    DetectTimeData *timed = DetectTimeParse(" 1 - 2 ");

    FAIL_IF_NULL(timed);
    FAIL_IF_NOT(timed->arg1 == 1);
    FAIL_IF_NOT(timed->arg2 == 2);
    FAIL_IF_NOT(timed->mode == DETECT_TIME_RA);

    DetectTimeFree(NULL, timed);

    PASS;
}

/**
 * \test DetectTimeParseTest06 is a test for setting up an valid time values with
 *       invalid "=" operator and include spaces arround the given values.
 */

static int DetectTimeParseTest06 (void)
{
    DetectTimeData *timed = DetectTimeParse(" 1 = 2 ");
    FAIL_IF_NOT_NULL(timed);
    PASS;
}

/**
 * \test DetectTimeParseTest07 is a test for setting up an valid time values with
 *       invalid "<>" operator and include spaces arround the given values.
 */

static int DetectTimeParseTest07 (void)
{
    DetectTimeData *timed = DetectTimeParse(" 1<>2 ");
    FAIL_IF_NOT_NULL(timed);
    PASS;
}

/**
 * \brief this function registers unit tests for DetectTime
 */
void DetectTimeRegisterTests(void)
{
    UtRegisterTest("DetectTimeParseTest01", DetectTimeParseTest01);
    UtRegisterTest("DetectTimeParseTest02", DetectTimeParseTest02);
    UtRegisterTest("DetectTimeParseTest03", DetectTimeParseTest03);
    UtRegisterTest("DetectTimeParseTest04", DetectTimeParseTest04);
    UtRegisterTest("DetectTimeParseTest05", DetectTimeParseTest05);
    UtRegisterTest("DetectTimeParseTest06", DetectTimeParseTest06);
    UtRegisterTest("DetectTimeParseTest07", DetectTimeParseTest07);
}

