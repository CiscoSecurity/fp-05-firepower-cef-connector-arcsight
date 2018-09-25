"""
Converts a dict to a csv
"""
#********************************************************************
#      File:    csv.py
#      Author:  Sam Strachan
#
#      Description:
#       CSV adapter
#
#      Copyright (c) 2017 by Cisco Systems, Inc.
#
#       ALL RIGHTS RESERVED. THESE SOURCE FILES ARE THE SOLE PROPERTY
#       OF CISCO SYSTEMS, Inc. AND CONTAIN CONFIDENTIAL  AND PROPRIETARY
#       INFORMATION.  REPRODUCTION OR DUPLICATION BY ANY MEANS OF ANY
#       PORTION OF THIS SOFTWARE WITHOUT PRIOR WRITTEN CONSENT OF
#       CISCO SYSTEMS, Inc. IS STRICTLY PROHIBITED.
#
#*********************************************************************/

from __future__ import absolute_import

import csv
import estreamer.crossprocesslogging as logging
from estreamer.common import convert

def __logger():
    return logging.getLogger(__name__)



def toValue( value, quoteAlways = False ):
    """Guarantees a csv safe value"""
    try:
        if value is None:
            return "NULL"

        if isinstance( value, basestring ):
            value = value.encode( 'utf-8' )
        else:
            value = str( value )

        isQuoted = quoteAlways or ',' in value or '"' in value

        if isQuoted:
            if '"' in value:
                value = value.replace('"', '""')

            value = '"' + value + '"'

        return value

    except UnicodeEncodeError:
        raise



def __to_line(dictionary, keys):
    """Converts dictionary to csv line"""
    vals = []
    for key in keys:
        if key not in dictionary:
            value = 'NULL'

        else:
            value = toValue( dictionary[key] )

        vals.append( value )

    line = ','.join(vals) + '\n'
    return line



def __to_lines( items, cols ):
    """Converts json objects to intermediate string array"""
    lines = []

    for key in items:
        if isinstance( items, dict ):
            item = items[key]
        else:
            item = key

        if item != None:
            line = __to_line( item, cols )
            lines.append(line)

    return lines



def dumps( objects, filepath, cols ):
    """Outputs the the json objects to a csv"""
    fileheader = ",".join(cols) + "\n"
    with open(filepath, "w") as outfile:
        outfile.write(fileheader)

    lines = __to_lines(objects, cols)
    for line in lines:
        with open(filepath, "a") as outfile:
            outfile.write(line)

    __logger().info("Written %i records to %s", len(lines), filepath)



def __from_csv_val( value ):
    return convert.infer(value)



def loads( filepath ):
    """Reads a CSV into an object list"""
    with open(filepath, 'rb') as csvfile:
        reader = csv.reader(csvfile)
        table = list(reader)

    if len(table) == 0:
        return []

    header = table[0]

    data = []
    for row in table[1:]:
        item = {}
        for columnIndex, key in enumerate(header):
            item[key] = __from_csv_val(row[columnIndex])
        data.append(item)

    __logger().info("Read %i records from %s", len(data), filepath)
    return data
