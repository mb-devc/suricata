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

/**
 * \file
 *
 * \author XXX
 */

#ifndef _DETECT_TIME_H
#define	_DETECT_TIME_H

#define DETECT_TIME_LT   0   /**< "less than" operator */
#define DETECT_TIME_EQ   1   /**< "equals" operator (default) */
#define DETECT_TIME_GT   2   /**< "greater than" operator */
#define DETECT_TIME_RA   3   /**< "range" operator */

typedef struct DetectTimeData_ {
    uint8_t arg1;   /**< first arg value in the signature*/
    uint8_t arg2;   /**< second arg value in the signature, in case of range
                         operator*/
    uint8_t mode;   /**< operator used in the signature */
} DetectTimeData;

void DetectTimeRegister(void);

#endif	/* _DETECT_TIME_H */

