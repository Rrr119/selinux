"""Aggregate AVC denials by process and path.

The aggregation is intentionally independent from policy analysis.  It
reduces noisy audit output while retaining the type information required to
produce exact (least-privilege) allow rules.
"""

UNKNOWN = "<unknown>"


class AVCGroup:
    """AVC denials for one process, path, and type-enforcement target."""

    def __init__(self, process, path, src_type, tgt_type, obj_class):
        self.process = process
        self.path = path
        self.src_type = src_type
        self.tgt_type = tgt_type
        self.obj_class = obj_class
        self.accesses = set()
        self.pids = set()
        self.count = 0

    def add(self, avc):
        self.accesses.update(avc.accesses)
        if avc.pid is not None:
            self.pids.add(avc.pid)
        self.count += 1

    @property
    def perms(self):
        return sorted(self.accesses)

    @property
    def target(self):
        return "self" if self.src_type == self.tgt_type else self.tgt_type

    def suggestion(self, rule_type="allow", cil=False):
        perms = " ".join(self.perms)
        if cil:
            return "(%s %s %s (%s (%s)))" % (
                rule_type, self.src_type, self.target,
                self.obj_class, perms)
        if len(self.perms) > 1:
            perms = "{ %s }" % perms
        return "%s %s %s:%s %s;" % (
            rule_type, self.src_type, self.target,
            self.obj_class, perms)


def _process_key(avc):
    # Keep processes with the same executable/comm but different SELinux
    # domains separate: their policy suggestions are not interchangeable.
    process = avc.exe or avc.comm or UNKNOWN
    return (avc.scontext.type, process, avc.comm)


def _process_label(avc):
    if avc.exe and avc.comm and avc.exe != avc.comm:
        return "%s (%s)" % (avc.exe, avc.comm)
    return avc.exe or avc.comm or avc.scontext.type


def _path_key(avc):
    return avc.path or avc.name or UNKNOWN


def aggregate_avcs(avc_msgs, avc_filter=None, only_denials=True):
    """Return AVC denials grouped by process and path.

    Groups are sorted by process and path.  Each group unions all denied
    permissions for its type-enforcement tuple, which is the smallest set of
    permissions needed to describe that group's denials.
    """
    groups = {}
    for avc in avc_msgs:
        if only_denials and not avc.denial:
            continue
        if avc_filter and not avc_filter.filter(avc):
            continue

        path = _path_key(avc)
        key = (_process_key(avc), path, avc.scontext.type,
               avc.tcontext.type, avc.tclass)
        group = groups.get(key)
        if group is None:
            group = AVCGroup(_process_label(avc), path,
                             avc.scontext.type, avc.tcontext.type,
                             avc.tclass)
            groups[key] = group
        group.add(avc)

    return sorted(groups.values(),
                  key=lambda group: (group.process, group.path,
                                     group.src_type, group.tgt_type,
                                     group.obj_class))


def minimal_rules(groups, rule_type="allow", cil=False):
    """Merge groups into unique rules with exact unioned permissions."""
    rules = {}
    for group in groups:
        key = (group.src_type, group.target, group.obj_class)
        rules.setdefault(key, set()).update(group.accesses)

    result = []
    for (src_type, tgt_type, obj_class), perms in sorted(rules.items()):
        if cil:
            result.append("(%s %s %s (%s (%s)))" % (
                rule_type, src_type, tgt_type, obj_class,
                " ".join(sorted(perms))))
        else:
            perms_str = " ".join(sorted(perms))
            if len(perms) > 1:
                perms_str = "{ %s }" % perms_str
            result.append("%s %s %s:%s %s;" % (
                rule_type, src_type, tgt_type, obj_class,
                perms_str))
    return result


def format_report(groups, comment_prefix="#", rule_type="allow", cil=False):
    """Format a human-readable aggregation report as policy comments."""
    lines = [
        "AVC denials grouped by process and path",
        "processes=%d groups=%d denials=%d" % (
            len(set(group.process for group in groups)),
            len(groups), sum(group.count for group in groups)),
        "minimal policy suggestions (exact denied permissions only)",
    ]

    for group in groups:
        lines.append("")
        lines.append("process: %s" % group.process)
        lines.append("  path: %s" % group.path)
        lines.append("  target: %s:%s" % (group.target, group.obj_class))
        lines.append("  denied: %s" % " ".join(group.perms))
        lines.append("  count: %d" % group.count)
        if group.pids:
            lines.append("  pids: %s" % " ".join(
                str(pid) for pid in sorted(group.pids)))
        lines.append("  suggestion: %s" % group.suggestion(
            rule_type=rule_type, cil=cil))

    return "\n".join("%s %s" % (comment_prefix, line) if line else comment_prefix
                     for line in lines)


# Short aliases for callers that prefer an aggregation-style API.
aggregate = aggregate_avcs
