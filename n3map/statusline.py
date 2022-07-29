import math
import re

from . import log

class ColorCode:
    def __init__(self, ccode):
        self.ccode = ccode

    def __str__(self):
        return self.ccode

    def __len__(self):
        return 0

def printlen(l):
    return sum(len(x) for x in l)

def truncate_line(l, width, cs):
    length = 0
    newlist = []
    for i,element in enumerate(l):
        newlength = length + len(element)
        if newlength > width:
            newlist.append(element[:width-newlength])
            newlist.append(ColorCode(cs.RESET))
            break
        newlist.append(element)
        length = newlength
    return newlist

def assemble_line(l):
    return ''.join(str(element) for element in l)

def compose_leftright(cs, leftlabels, leftvalues, rightlabels, rightvalues):
    leftline = []
    for lbl,val in zip(leftlabels, leftvalues):
        leftline += [*lbl , " = ", *val, '; ']

    rightline = [' ']
    for i,(lbl,val) in enumerate(zip(rightlabels, rightvalues)):
        if i > 0:
            rightline.append('; ')
        rightline += [*lbl , " = ", *val]
    rightline += [
            ColorCode(cs.DECO),
            ' ;;',
            ColorCode(cs.RESET),
            ]
    return leftline,rightline


def format_statusline_nsec3(width,
                zone,
                queries,
                records,
                hashes,
                coverage,
                queryrate,
                prediction
            ):
    cs = log.logger.colors
    # first line ======
    lines = []
    left = [
            ColorCode(cs.DECO),
            ";;",
            ColorCode(cs.RESET),
            " mapping ",
            ColorCode(cs.ZONE), str(zone), ColorCode(cs.RESET),
            " ",
            ]
    right = [
            ColorCode(cs.DECO),
            " ;;",
            ColorCode(cs.RESET),
            ]
    pad = width - printlen(left) - printlen(right)
    if prediction is not None and pad >= 10:
        if prediction < records:
            prediction = records
        ratio = records/float(prediction) if prediction > 0 else 0
        percentage = [
                ColorCode(cs.PROGRESS),
                "{0:3d}% ".format(int(ratio*100)),
                ColorCode(cs.RESET),
                ]
        proglen = pad-printlen(percentage)-2
        filllen = int(math.ceil(ratio*proglen))
        progress = [
            "[",
            ColorCode(cs.PROGRESSBAR),
            "{0:s}{1:s}".format("="*filllen," "*(proglen-filllen)),
            ColorCode(cs.RESET),
            "]"
            ]
        right =  percentage + progress + right
    elif pad > 0:
        right = ['.' * pad] + right
    lines.append(left + right)

    # second line =======
    leftlabels =  [['records'],['queries'],['hashes']]
    leftshortlabels =  [['r'],['q'],['h']]
    leftvalues = [
            [ColorCode(cs.RECORDS), "{0:3d}".format(records),
                ColorCode(cs.RESET)],
            [ColorCode(cs.NUMBERS), "{0:3d}".format(queries),
                ColorCode(cs.RESET)],
            [ColorCode(cs.NUMBERS), "{0:3d}".format(hashes),
                ColorCode(cs.RESET)],
            ]
    if prediction is not None:
        leftlabels.append("predicted zone size")
        leftshortlabels.append("pred")
        leftvalues += [
                [ColorCode(cs.NUMBERS), "{0:3d}".format(prediction),
                    ColorCode(cs.RESET)],
                ]
    rightlabels = [['q/s'], ['coverage']]
    rightshortlabels = [['q/s'], ['c']]
    rightvalues = [
            [ColorCode(cs.gradient(round(queryrate)/100.0)),
                "{0:.0f}".format(queryrate),
                ColorCode(cs.RESET)
                ],
            [ColorCode(cs.NUMBERS), "{0:11.6%}".format(coverage),
                ColorCode(cs.RESET)],
            ]
    left,right = compose_leftright(cs, leftlabels, leftvalues,
                                   rightlabels, rightvalues)
    leftprefix = [ ColorCode(cs.DECO), ';; ', ColorCode(cs.RESET), ]
    pad = width - printlen(leftprefix) - printlen(left) - printlen(right)
    if pad < 0:
        left,right = compose_leftright(cs, leftshortlabels, leftvalues,
                                       rightshortlabels, rightvalues)
        pad = width - printlen(leftprefix) - printlen(left) - printlen(right)
    if pad < 0:
        pad = 0

    lines.append([*leftprefix, *left, pad * '.', *right])

    return [assemble_line(truncate_line(l, width, cs)) for l in lines]

def format_statusline_nsec(width,
                zone,
                queries,
                records,
                queryrate
            ):

    cs = log.logger.colors
    mappinglabel = [
            ColorCode(cs.DECO),
            ";;",
            ColorCode(cs.RESET),
            " walking ",
            ColorCode(cs.ZONE), str(zone), ColorCode(cs.RESET),
            ": ",
            ]
    leftlabels =  [['records'],['queries']]
    leftvalues = [
            [ColorCode(cs.RECORDS), "{0:3d}".format(records),
                ColorCode(cs.RESET)],
            [ColorCode(cs.NUMBERS), "{0:3d}".format(queries),
                ColorCode(cs.RESET)],
            ]
    rightlabels = [['q/s']]
    rightvalues = [
            [
                ColorCode(cs.gradient(round(queryrate)/100.0)),
                "{0:.0f}".format(queryrate),
                ColorCode(cs.RESET),
            ]
            ]
    left,right = compose_leftright(cs, leftlabels, leftvalues,
                                   rightlabels, rightvalues)
    left = mappinglabel + left
    pad = width - printlen(left) - printlen(right)
    if pad < 0:
        pad = 0
    line = left + [pad * '.'] + right
    return [assemble_line(truncate_line(line, width, cs))]

