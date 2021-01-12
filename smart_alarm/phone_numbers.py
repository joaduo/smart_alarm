"""
smart_alarm
Copyright (c) 2020, Joaquin G. Duo

Code Licensed under LGPL License. See LICENSE file.
"""
from smart_alarm.solve_settings import solve_settings
import re


def is_phone(s):
    return re.match(r'\+?[0-9]+', s.strip())

def phone_to_name(phone):
    p2n = {}
    for n,p in solve_settings().names_to_phones.items():
        p = normalize_phone(str(p))
        p2n[p] = n
    return p2n.get(normalize_phone(phone), phone)

def name_to_phone(name):
    n2p = {}
    for n,p in solve_settings().names_to_phones.items():
        p = normalize_phone(str(p))
        n2p[n.lower()] = p
    return n2p.get(name.lower())

def normalize_phone(p):
    full = solve_settings().phone_length
    p = p.strip()
    #+54 2615 9639 94
    if len(p) < full:
        p = solve_settings().local_phone_prefix[:full - len(p)] + p
    return p

def split_phones(phones_str):
    def name2phone(ph):
        ph = ph.strip()
        if not ph:
            return ph
        if is_phone(ph):
            return normalize_phone(ph)
        else:
            return name_to_phone(ph)
    return set(name2phone(p) for p in phones_str.strip().split(',') if name2phone(p))

def remove_phone_prefix(s):
    s = normalize_phone(s)
    pref = solve_settings().local_phone_prefix
    if s.startswith(pref):
        return s[len(pref):]
    return s

def phones_to_str(phone_group, names=True):
    def beautify(ph):
        n = phone_to_name(ph)
        if names and n != ph:
            return n
        return remove_phone_prefix(ph)
    return ','.join(beautify(p) for p in sorted(phone_group))

