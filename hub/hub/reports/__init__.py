"""Grouped abuse reports (design M29 section 8.4 and 8.5).

``select`` finds reportable targets and queues grouped reports, ``render`` writes the text and
the X-ARF part (no node identity, no project name), ``rdap`` finds the abuse contact, ``send``
mails approved reports under the daily caps.
"""
