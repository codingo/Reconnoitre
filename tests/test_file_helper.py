#!/usr/bin/python
from unittest import TestCase
from Reconnoitre.lib.file_helper import FileHelper
import os


class TestFileHelper(TestCase):

    HOST = "34.94.3.143"
    IP_RANGE = "34.94.3.0-143"
    OUTPUT_DIR = os.path.join("results")
    OUTPUT_FILE = os.path.join("results", "targets.txt")
    INVALID_DIR = os.path.join("results", "InvalidDirectory")
    NEW_DIR = os.path.join("results", "NewDirectory")
    SAMPLE_NMAP = os.path.join('sample.nmap')

    def test_check_directory(self):
        res = FileHelper.check_directory(output_directory=self.OUTPUT_DIR)
        self.assertIsNotNone(res)
        self.assertTrue(os.path.exists(res))
        self.assertTrue(os.path.isdir(res))
        self.assertFalse(os.path.exists(self.INVALID_DIR))
        res2 = FileHelper.check_directory(output_directory=self.INVALID_DIR)
        self.assertTrue(os.path.exists(res2))
        self.assertTrue(os.path.isdir(res2))
        os.rmdir(res2)

    def test_make_directory(self):
        if os.path.exists(self.NEW_DIR):
            os.rmdir(self.NEW_DIR)

        FileHelper.make_directory(output_directory=self.NEW_DIR)
        self.assertTrue(os.path.exists(self.NEW_DIR))
        self.assertTrue(os.path.isdir(self.NEW_DIR))
        self.assertRaises(FileExistsError, FileHelper.make_directory, output_directory=self.NEW_DIR)
        os.rmdir(self.NEW_DIR)

    def test_check_file(self):
        res = FileHelper.check_file(self.OUTPUT_FILE)
        self.assertIsNotNone(res)
        self.assertTrue(os.path.exists(res))
        self.assertTrue(os.path.isfile(res))
        os.remove(self.OUTPUT_FILE)

    def test_make_file(self):
        if os.path.exists(self.OUTPUT_FILE):
            os.remove(self.OUTPUT_FILE)

        FileHelper.make_file(self.OUTPUT_FILE)
        self.assertIsNotNone(self.OUTPUT_FILE)
        self.assertTrue(os.path.exists(self.OUTPUT_FILE))
        self.assertTrue(os.path.isfile(self.OUTPUT_FILE))
        os.remove(self.OUTPUT_FILE)

    def test_load_targets(self):
        res = FileHelper.load_targets(target_hosts=self.HOST, output_directory=self.OUTPUT_DIR, quiet=False)
        self.assertEqual(res, f'{self.OUTPUT_DIR}/targets.txt')

    def test_expand_targets(self):

        FileHelper.expand_targets(target_hosts=self.IP_RANGE, output_directory=self.OUTPUT_DIR)
        self.assertTrue(os.path.exists(f'{self.OUTPUT_DIR}/targets.txt'))
        self.assertTrue(os.path.isfile(f'{self.OUTPUT_DIR}/targets.txt'))
        os.remove(f'{self.OUTPUT_DIR}/targets.txt')

    def test_create_dir_structure(self):
        FileHelper.create_dir_structure(ip_address=self.HOST, output_directory=self.OUTPUT_DIR)
        res_dir = f'{self.OUTPUT_DIR}/{self.HOST}'
        self.assertTrue(os.path.exists(res_dir))
        self.assertTrue(os.path.isdir(res_dir))
        self.assertTrue(os.path.exists(f'{res_dir}/proof.txt'))
        self.assertTrue(os.path.isfile(f'{res_dir}/proof.txt'))
        self.assertTrue(os.path.exists(f'{res_dir}/exploit'))
        self.assertTrue(os.path.isdir(f'{res_dir}/exploit'))
        self.assertTrue(os.path.exists(f'{res_dir}/loot'))
        self.assertTrue(os.path.isdir(f'{res_dir}/loot'))
        self.assertTrue(os.path.exists(f'{res_dir}/scans'))
        self.assertTrue(os.path.isdir(f'{res_dir}/scans'))

        # remove the added directories
        os.remove(f'{res_dir}/proof.txt')
        os.rmdir(f'{res_dir}/exploit/')
        os.rmdir(f'{res_dir}/loot/')
        os.rmdir(f'{res_dir}/scans/')
        os.rmdir(f'{res_dir}/')

    def test_write_recommendations(self):
        FileHelper.write_recommendations(results=self.SAMPLE_NMAP, ip_address=self.HOST, outputdir=self.OUTPUT_DIR)
        res_dir = f'{self.OUTPUT_DIR}/{self.HOST}'
        self.assertTrue(os.path.exists(f'{res_dir}_findings.txt'))
        os.remove(f'{res_dir}_findings.txt')

    def test_get_config_options(self):
        flags = ['nmap', 'quickscan']
        res = FileHelper.get_config_options(*flags)
        self.assertIsNotNone(res)
        self.assertEqual(res, '-sC -sV -Pn --disable-arp-ping')
