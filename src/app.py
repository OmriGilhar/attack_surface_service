from typing import Optional, Union
import json
import time
import sys
import os

from flask import Flask, request, jsonify, g
from flask_api import status
from multiprocessing import Value
# Relative imports and and libs due to testing parent issue
try:
    from exceptions.http_request_error import HttpRequestEnums
    from entities.cloud_env import CloudEnv
except ModuleNotFoundError:
    from src.exceptions.http_request_error import HttpRequestEnums
    from src.entities.cloud_env import CloudEnv

app = Flask(__name__)
VERSION: str = '1'
ROUTE_PREFIX: str = f'/api/v{VERSION}'
REQUEST_COUNT = Value('i', 0)
AVERAGE_REQUEST_PROCESS: int = 0
cloud_env: Union[CloudEnv, None] = None


def _validate_attack_request(vm_id) -> Optional[tuple[int, str]]:
    """
    Checks if the requests come with an vm_id.

    :param vm_id: the id of the vm.
    :return: None if the vm exists, otherwise, return an error message with
        error status code to return.
    """
    if not vm_id:
        return HttpRequestEnums.BAD_REQUEST, status.HTTP_400_BAD_REQUEST
    return None


def _stats() -> dict:
    """
    Compose a statistic dictionary to return as a response, consist of
    cloud information such as:
    * How many VM are running at the cloud.
    """
    global REQUEST_COUNT
    global AVERAGE_REQUEST_PROCESS
    return {
        'vm_count': cloud_env.get_vm_size(),
        'request_count': REQUEST_COUNT.value,
        'average_request_time': AVERAGE_REQUEST_PROCESS
    }


@app.before_request
def before_request():
    """
    Pre-request flow, start timing the request duration.
    """
    g.start = time.time()


@app.after_request
def after_request(res):
    """
    A post request flow, check the average time of a request, then run
    calculate the mean value of the request time overall.

    :param res: The response instance.
    :return: The response instance.
    """
    global AVERAGE_REQUEST_PROCESS
    delta_time = time.time() - g.start
    if not AVERAGE_REQUEST_PROCESS:
        AVERAGE_REQUEST_PROCESS = delta_time
    AVERAGE_REQUEST_PROCESS = (AVERAGE_REQUEST_PROCESS + delta_time)/2
    return res


@app.route(f"{ROUTE_PREFIX}/attack", methods=['GET'])
def get_attacks():
    """
     Response the an attack surface for a specific VM.

    """
    global REQUEST_COUNT
    with REQUEST_COUNT.get_lock():
        REQUEST_COUNT.value += 1
    vm_id = request.args.get('vm_id', None)
    return_code = _validate_attack_request(vm_id)
    return jsonify(cloud_env.get_potential_attacks(vm_id)) if not return_code \
        else return_code


@app.route(f"{ROUTE_PREFIX}/stats", methods=['GET'])
def get_statistics():
    """
    Response the API statistics

    Including :

    * Number of virtual machines in the cloud environment,
    * Number of requests to all endpoints
    * Average request processing time.
    """
    global AVERAGE_REQUEST_PROCESS
    global REQUEST_COUNT
    with REQUEST_COUNT.get_lock():
        REQUEST_COUNT.value += 1
    return _stats()


def init_cloud(cloud_details: dict):
    """
    Init the cloud in a public function in order to run a system test.
    :param cloud_details: A dictionary of all the cloud details including a
            list of Virtual environment and a list of Firewall rules.
    :type cloud_details: dict
    """
    global cloud_env
    cloud_env = CloudEnv(cloud_details)


def _usage():
    """
    Show the user a usage message.
    """
    print('[ERROR] - No data json has been entered')
    print('Usage:')
    print('\tpython3 app.py <data_json_path>')
    exit(1)


if __name__ == '__main__':
    if len(sys.argv) < 2:
        _usage()
    cloud_json = os.path.abspath(sys.argv[1])
    with open(cloud_json, 'r') as upload:
        init_cloud(json.load(upload))
    app.run(debug=True)
