from unittest import main, TestCase
import json
import os

from src.app import app, init_cloud, ROUTE_PREFIX


class TestAPI(TestCase):
    def __init__(self, *args, **kwargs):
        super(TestAPI, self).__init__(*args, **kwargs)
        app.testing = True
        testing_json = os.path.abspath('./system_data_mock.json')
        with open(testing_json, 'r') as upload:
            init_cloud(json.load(upload))

    def test_01_get_stats(self):
        expected = {
            "average_request_time": 0,
            "request_count": 1,
            "vm_count": 2
        }
        with app.test_client() as client:
            result = client.get(f'{ROUTE_PREFIX}/stats')
            self.assertEqual(result.json, expected)

    def test_02_attack_surface(self):
        expected = ["vm-c7bac01a07"]
        vm = {'vm_id': 'vm-a211de'}
        with app.test_client() as client:
             result = client.get(f'{ROUTE_PREFIX}/attack', query_string=vm)
        self.assertEqual(expected, result.json)

    def test_03_no_vm_id(self):
        no_vm = {'vm_id': 'NoVMTest'}
        with app.test_client() as client:
            result = client.get(f'{ROUTE_PREFIX}/attack', query_string=no_vm)
        self.assertEqual(result.json, [])

    def test_04_get_stats(self):
        expected = {
            "request_count": 4,
            "vm_count": 2
        }
        with app.test_client() as client:
            result = client.get(f'{ROUTE_PREFIX}/stats')
            self.assertEqual(
                result.json['request_count'],
                expected['request_count']
            )
            self.assertEqual(
                result.json['vm_count'],
                expected['vm_count']
            )


if __name__ == "__main__":
    main()
