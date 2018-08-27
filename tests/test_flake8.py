#!/usr/bin/env python
# -*- coding: utf-8 -*-
from subprocess import call


def test_flake8():
    return_code = call(['flake8'])
    assert return_code == 0
