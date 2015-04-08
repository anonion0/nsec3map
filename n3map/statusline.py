import math

def compose_leftright(leftlabels, leftvalues, rightlabels, rightvalues):
    left = ('; '.join([lbl + " = " + val for lbl,val in zip(leftlabels,leftvalues)])+'; ')
    right = ' ' +'; '.join([lbl + " = " + val for lbl,val in zip(rightlabels,rightvalues)]) + ' ;;'
    return left,right


def format_statusline_nsec3(width,
                zone,
                queries,
                records,
                hashes,
                coverage,
                queryrate,
                prediction
            ):
    # first line ======
    lines = []
    left = ";; mapping {0:s}: ".format(zone)
    right = " ;;"
    pad = width - len(left) - len(right)
    if prediction is not None and pad >= 10:
        if prediction < records:
            prediction = records
        ratio = records/float(prediction) if prediction > 0 else 0
        percentage = "{0:d}% ".format(int(ratio*100))
        prlen = pad-len(percentage)-2
        filllen = int(math.ceil(ratio*prlen))
        progress = "[{0:s}{1:s}]".format("="*filllen," "*(prlen-filllen))
        right =  percentage + progress + right
    elif pad > 0:
        right = '.' * pad + right
    lines.append(left + right)

    # second line =======
    leftlabels =  ['records','queries','hashes']
    leftshortlabels =  ['r','q','h']
    leftvalues = ["{0:3d}".format(records),
                  "{0:3d}".format(queries),
                  "{0:3d}".format(hashes)
            ]
    if prediction is not None:
        leftlabels.append("predicted zone size")
        leftshortlabels.append("pred")
        leftvalues.append("{0:3d}".format(prediction))
    rightlabels = ['q/s', 'coverage']
    rightshortlabels = ['q/s', 'c']
    rightvalues = ["{0:.0f}".format(queryrate),
                   "{0:11.6%}".format(coverage)
            ]
    left,right = compose_leftright(leftlabels, leftvalues,
                                   rightlabels, rightvalues)
    left = ";; " + left
    if width < len(left) + len(right):
        left,right = compose_leftright(leftshortlabels, leftvalues,
                                       rightshortlabels, rightvalues)
        left = ";; " + left
    pad = width - len(left)
    if pad > 0:
        right = right.rjust(pad, ".")
    lines.append(left + right)
    return [l[:width] for l in lines]

def format_statusline_nsec(width,
                zone,
                queries,
                records,
                queryrate
            ):

    mappinglabel = ";; walking {0:s}: ".format(zone)
    leftlabels =  ['records','queries']
    leftvalues = ["{0:3d}".format(records),
                  "{0:3d}".format(queries),
            ]
    rightlabels = ['q/s']
    rightvalues = ["{0:.0f}".format(queryrate)]
    left,right = compose_leftright(leftlabels, leftvalues,
                                   rightlabels, rightvalues)
    left = mappinglabel + left
    pad = width - len(left)
    if pad > 0:
        right = right.rjust(pad, '.')
    line = left + right
    return [line[:width]]

