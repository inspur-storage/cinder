# Copyright 2018 Inspur Corp.
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

"""
Volume driver test for Inspur AS13000
"""

import ddt
import json
import mock
from oslo_config import cfg
import requests
import time
import random

from cinder import context
from cinder import exception
from cinder import test
from cinder.volume import configuration
from cinder.volume import utils as volume_utils
from cinder.volume.drivers.inspur.as13000 import as13000_driver
from cinder.tests.unit import fake_snapshot
from cinder.tests.unit import fake_volume

CONF = cfg.CONF

test_config = configuration.Configuration(None)
test_config.san_ip = 'some_ip'
test_config.san_api_port = 'as13000_api_port'
test_config.san_login = 'username'
test_config.san_password = 'password'
test_config.inspur_as13000_ipsan_pool = 'fakepool'
test_config.volume_backend_name = 'as13000'
test_config.as13000_data_pool_type = 1
test_config.as13000_mete_pool = 'mete_pool'
test_config.chap_username = 'fakeuser'
test_config.chap_password = 'fakepass'


class FakeResponse(object):
    def __init__(self, status, output):
        self.status_code = status
        self.text = 'return message'
        self._json = output

    def json(self):
        return self._json

    def close(self):
        pass


# @ddt.ddt
# class RestAPIExecutorTestCase(test.TestCase):
#     def setUp(self):
#         self.rest_api = as13000_driver.RestAPIExecutor(
#             test_config.san_ip,
#             test_config.san_api_port,
#             test_config.san_login,
#             test_config.san_password)
#         super(RestAPIExecutorTestCase, self).setUp()
#
#     def test_logins(self):
#         mock_login = self.mock_object(self.rest_api, 'login',
#                                       mock.Mock(return_value='fake_token'))
#         self.rest_api.logins()
#         mock_login.assert_called_once()
#
#     def test_login(self):
#         fake_response = {
#             'token': 'fake_token',
#             'expireTime': '7200',
#             'type': 0}
#         mock_sra = self.mock_object(self.rest_api, 'send_rest_api',
#                                     mock.Mock(return_value=fake_response))
#         result = self.rest_api.login()
#
#         self.assertEqual('fake_token', result)
#
#         login_params = {'name': test_config.san_login,
#                         'password': test_config.san_password}
#         mock_sra.assert_called_once_with(method='security/token',
#                                          params=login_params,
#                                          request_type='post')
#
#     def test_logout(self):
#         mock_sra = self.mock_object(self.rest_api, 'send_rest_api',
#                                     mock.Mock(return_value=None))
#         self.rest_api.logout()
#         mock_sra.assert_called_once_with(
#             method='security/token', request_type='delete')
#
#     @ddt.data(True, False)
#     def test_refresh_token(self, force):
#         mock_login = self.mock_object(self.rest_api, 'login',
#                                       mock.Mock(return_value='fake_token'))
#         mock_logout = self.mock_object(self.rest_api, 'logout',
#                                        mock.Mock())
#         self.rest_api.refresh_token(force)
#         if force is not True:
#             mock_logout.assert_called_once_with()
#         mock_login.assert_called_once_with()
#
#     def test_send_rest_api(self):
#         expected = {'value': 'abc'}
#         mock_sa = self.mock_object(self.rest_api, 'send_api',
#                                    mock.Mock(return_value=expected))
#         result = self.rest_api.send_rest_api(
#             method='fake_method',
#             params='fake_params',
#             request_type='fake_type')
#         self.assertEqual(expected, result)
#         mock_sa.assert_called_once_with(
#             'fake_method',
#             'fake_params',
#             'fake_type')
#
#     def test_send_rest_api_retry(self):
#         expected = {'value': 'abc'}
#         mock_sa = self.mock_object(
#             self.rest_api,
#             'send_api',
#             mock.Mock(side_effect=(exception.VolumeDriverException, expected)))
#         # mock.Mock(side_effect=exception.NetworkException))
#         mock_rt = self.mock_object(self.rest_api, 'refresh_token', mock.Mock())
#         result = self.rest_api.send_rest_api(
#             method='fake_method',
#             params='fake_params',
#             request_type='fake_type'
#         )
#         self.assertEqual(expected, result)
#
#         mock_sa.assert_called_with(
#             'fake_method',
#             'fake_params',
#             'fake_type')
#         mock_rt.assert_called_with(force=True)
#
#     def test_send_rest_api_3times_fail(self):
#         mock_sa = self.mock_object(
#             self.rest_api, 'send_api', mock.Mock(
#                 side_effect=(exception.VolumeDriverException)))
#         mock_rt = self.mock_object(self.rest_api, 'refresh_token', mock.Mock())
#         self.assertRaises(
#             exception.VolumeDriverException,
#             self.rest_api.send_rest_api,
#             method='fake_method',
#             params='fake_params',
#             request_type='fake_type')
#         mock_sa.assert_called_with('fake_method',
#                                    'fake_params',
#                                    'fake_type')
#         mock_rt.assert_called_with(force=True)
#
#     def test_send_rest_api_backend_error_fail(self):
#         mock_sa = self.mock_object(self.rest_api, 'send_api', mock.Mock(
#             side_effect=(exception.VolumeBackendAPIException(
#                 'fake_error_message'))))
#         mock_rt = self.mock_object(self.rest_api, 'refresh_token')
#         self.assertRaises(
#             exception.VolumeDriverException,
#             self.rest_api.send_rest_api,
#             method='fake_method',
#             params='fake_params',
#             request_type='fake_type')
#         mock_sa.assert_called_with('fake_method',
#                                    'fake_params',
#                                    'fake_type')
#         mock_rt.assert_not_called()
#
#     @ddt.data(
#         {'method': 'fake_method', 'request_type': 'post', 'params':
#             {'fake_param': 'fake_value'}},
#         {'method': 'fake_method', 'request_type': 'get', 'params':
#             {'fake_param': 'fake_value'}},
#         {'method': 'fake_method', 'request_type': 'delete', 'params':
#             {'fake_param': 'fake_value'}},
#         {'method': 'fake_method', 'request_type': 'put', 'params':
#             {'fake_param': 'fake_value'}}, )
#     @ddt.unpack
#     def test_send_api(self, method, params, request_type):
#         self.rest_api._token_pool = ['fake_token']
#         if request_type in ('post', 'delete', 'put'):
#             fake_output = {'code': 0, 'message': 'success'}
#         elif request_type == 'get':
#             fake_output = {'code': 0, 'data': 'fake_date'}
#         mock_request = self.mock_object(
#             requests, request_type, mock.Mock(
#                 return_value=FakeResponse(
#                     200, fake_output)))
#         self.rest_api.send_api(
#             method,
#             params=params,
#             request_type=request_type)
#         mock_request.assert_called_once_with(
#             'http://%s:%s/rest/%s' %
#             (test_config.san_ip,
#              test_config.san_api_port,
#              method),
#             data=json.dumps(params),
#             headers={'X-Auth-Token': 'fake_token'})
#
#     @ddt.data({'method': r'security/token',
#                'params': {'name': test_config.san_login,
#                           'password': test_config.san_password},
#                'request_type': 'post'},
#               {'method': r'security/token',
#                'params': '',
#                'request_type': 'delete'})
#     @ddt.unpack
#     def test_send_api_access_success(self, method, params, request_type):
#         if request_type == 'post':
#             fake_value = {'code': 0, 'data': {
#                 'token': 'fake_token',
#                 'expireTime': '7200',
#                 'type': 0}}
#             mock_requests = self.mock_object(
#                 requests, 'post', mock.Mock(
#                     return_value=FakeResponse(
#                         200, fake_value)))
#             result = self.rest_api.send_api(method, params, request_type)
#             self.assertEqual(fake_value['data'], result)
#             mock_requests.assert_called_once_with(
#                 'http://%s:%s/rest/%s' %
#                 (test_config.san_ip,
#                  test_config.san_api_port,
#                  method),
#                 data=json.dumps(params),
#                 headers=None)
#         if request_type == 'delete':
#             fake_value = {'code': 0, 'message': 'Success!'}
#             self.rest_api._token_pool = ['fake_token']
#             mock_requests = self.mock_object(
#                 requests, 'delete', mock.Mock(
#                     return_value=FakeResponse(
#                         200, fake_value)))
#             self.rest_api.send_api(method, params, request_type)
#             mock_requests.assert_called_once_with(
#                 'http://%s:%s/rest/%s' %
#                 (test_config.san_ip,
#                  test_config.san_api_port,
#                  method),
#                 data=json.dumps(''),
#                 headers={'X-Auth-Token': 'fake_token'})
#
#     def test_send_api_wrong_access_fail(self):
#         req_params = {'method': r'security/token',
#                       'params': {'name': test_config.san_login,
#                                  'password': 'fake_password'},
#                       'request_type': 'post'}
#         fake_value = {'message': ' User name or password error.', 'code': 400}
#         mock_request = self.mock_object(
#             requests, 'post', mock.Mock(
#                 return_value=FakeResponse(
#                     200, fake_value)))
#         self.assertRaises(
#             exception.VolumeBackendAPIException,
#             self.rest_api.send_api,
#             method=req_params['method'],
#             params=req_params['params'],
#             request_type=req_params['request_type'])
#         mock_request.assert_called_once_with(
#             'http://%s:%s/rest/%s' %
#             (test_config.san_ip,
#              test_config.san_api_port,
#              req_params['method']),
#             data=json.dumps(
#                 req_params['params']),
#             headers=None)
#
#     def test_send_api_token_overtime_fail(self):
#         self.rest_api._token_pool = ['fake_token']
#         fake_value = {'method': 'fake_url',
#                       'params': 'fake_params',
#                       'reuest_type': 'post'}
#         fake_out_put = {'message': 'Unauthorized access!', 'code': 301}
#         mock_requests = self.mock_object(
#             requests, 'post', mock.Mock(
#                 return_value=FakeResponse(
#                     200, fake_out_put)))
#         self.assertRaises(exception.VolumeDriverException,
#                           self.rest_api.send_api,
#                           method='fake_url',
#                           params='fake_params',
#                           request_type='post')
#         mock_requests.assert_called_once_with(
#             'http://%s:%s/rest/%s' %
#             (test_config.san_ip,
#              test_config.san_api_port,
#              fake_value['method']),
#             data=json.dumps('fake_params'),
#             headers={
#                 'X-Auth-Token': 'fake_token'})
#
#     def test_send_api_fail(self):
#         self.rest_api._token_pool = ['fake_token']
#         fake_output = {'code': 'fake_code', 'message': 'fake_message'}
#         mock_request = self.mock_object(
#             requests, 'post', mock.Mock(
#                 return_value=FakeResponse(
#                     200, fake_output)))
#         self.assertRaises(
#             exception.VolumeBackendAPIException,
#             self.rest_api.send_api,
#             method='fake_method',
#             params='fake_params',
#             request_type='post')
#         mock_request.assert_called_once_with(
#             'http://%s:%s/rest/%s' %
#             (test_config.san_ip,
#              test_config.san_api_port,
#              'fake_method'),
#             data=json.dumps('fake_params'),
#             headers={'X-Auth-Token': 'fake_token'}
#         )
#

@ddt.ddt
class AS13000DriverTestCase(test.TestCase):
    def __init__(self, *args, **kwds):
        super(AS13000DriverTestCase, self).__init__(*args, **kwds)
        self._ctxt = context.get_admin_context()
        self.configuration = test_config

    def setUp(self):
        self.rest_api = as13000_driver.RestAPIExecutor(
            test_config.san_ip,
            test_config.san_api_port,
            test_config.san_login,
            test_config.san_password)
        self.as13000_san = as13000_driver.AS13000Driver(
            configuration=self.configuration)
        super(AS13000DriverTestCase, self).setUp()

    def test_do_setup(self):
        fake_nodes = [{'healthStatus': 1}, {
            'healthStatus': 1}, {'healthStatus': 1}]
        mock_login = self.mock_object(as13000_driver.RestAPIExecutor,
                                      'logins', mock.Mock())
        mock_gcs = self.mock_object(
            self.as13000_san,
            '_get_cluster_status',
            mock.Mock(
                return_value=fake_nodes))
        mock_vpe = self.mock_object(self.as13000_san, '_validate_pools_exist',
                                    mock.Mock())
        mock_cmp = self.mock_object(
            self.as13000_san,
            '_check_meta_pool',
            mock.Mock())
        self.as13000_san.do_setup(self._ctxt)
        mock_login.assert_called_once()
        mock_gcs.assert_called_once()
        mock_vpe.assert_called_once()
        mock_cmp.assert_called_once()

    def test_check_for_setup_error(self):
        mock_sg = self.mock_object(configuration.Configuration, 'safe_get',
                                   mock.Mock(return_value='fake_config'))
        self.as13000_san.nodes = [{'fakenode': 'fake_name'}]
        self.as13000_san.check_for_setup_error()
        mock_sg.assert_called()

    def test_check_for_setup_error_no_healthy_node_fail(self):
        mock_sg = self.mock_object(configuration.Configuration, 'safe_get',
                                   mock.Mock(return_value='fake_config'))
        self.as13000_san.nodes = []
        self.assertRaises(
            exception.VolumeDriverException,
            self.as13000_san.check_for_setup_error)
        mock_sg.assert_called()

    def test_check_for_setup_error_no_config_fail(self):
        mock_sg = self.mock_object(configuration.Configuration, 'safe_get',
                                   mock.Mock(return_value=None))
        self.as13000_san.nodes = []
        self.assertRaises(exception.InvalidInput,
                          self.as13000_san.check_for_setup_error)
        mock_sg.assert_called()

    def test__validate_pools_exist(self):
        fake_pool_backend = [{'pool_name': 'fake_pool'},
                             {'pool_name': 'fake_pool1'}]
        self.as13000_san.pools = ['fake_pool']
        mock_gps = self.mock_object(self.as13000_san, '_get_pools_stats',
                                    mock.Mock(return_value=fake_pool_backend))
        self.as13000_san._validate_pools_exist()
        mock_gps.assert_called_once()

    def test__validate_pools_exist_fail(self):
        fake_pool_backend = [{'pool_name': 'fake_pool0'},
                             {'pool_name': 'fake_pool1'}]
        self.as13000_san.pools = ['fake_pool']
        mock_gps = self.mock_object(self.as13000_san, '_get_pools_stats',
                                    mock.Mock(return_value=fake_pool_backend))
        self.assertRaises(
            exception.InvalidInput,
            self.as13000_san._validate_pools_exist)
        mock_gps.assert_called_once()

    def test_create_volume(self):
        volume = fake_volume.fake_volume_obj(self._ctxt, host='fakehost')
        mock_eh = self.mock_object(volume_utils,
                                   'extract_host',
                                   mock.Mock(return_value='fake_pool'))
        mock_tnd = self.mock_object(
            self.as13000_san, '_trans_name_down', mock.Mock(
                return_value='fake_name'))
        mock_rest = self.mock_object(as13000_driver.RestAPIExecutor,
                                     'send_rest_api',
                                     mock.Mock())
        self.as13000_san.create_volume(volume)
        mock_eh.assert_called_once_with(volume['host'], level='pool')
        mock_tnd.assert_called_once_with(volume['name'])
        mock_rest.assert_called_once_with(
            method='block/lvm',
            params={"dataPool": 'fake_pool',
                    "name": 'fake_name',
                    "capacity": volume['size'] * 1024,
                    "dataPoolType": test_config.as13000_data_pool_type,
                    "metaPool": test_config.as13000_mete_pool},
            request_type='post')

    @ddt.data(1, 2)
    def test_create_volume_from_snapshot(self, size):
        volume = fake_volume.fake_volume_obj(self._ctxt, size=size)
        volume2 = fake_volume.fake_volume_obj(self._ctxt)
        snapshot = fake_snapshot.fake_snapshot_obj(self._ctxt, volume=volume2)
        mock_eh = self.mock_object(volume_utils,
                                   'extract_host',
                                   mock.Mock(return_value='fake_pool'))
        mock_tnd = self.mock_object(
            self.as13000_san, '_trans_name_down', mock.Mock(
                side_effect=('source_volume', 'dest_volume', 'snapshot')))
        mock_rest = self.mock_object(as13000_driver.RestAPIExecutor,
                                     'send_rest_api',
                                     mock.Mock())

        mock_ev = self.mock_object(
            self.as13000_san,
            'extend_volume',
            mock.Mock())

        self.as13000_san.create_volume_from_snapshot(volume, snapshot)

        mock_eh.assert_called()
        mock_tnd.assert_called()
        params = {
            'srcVolumeName': 'source_volume',
            'srcPoolName': 'fake_pool',
            'snapName': 'snapshot',
            'destVolumeName': 'dest_volume',
            'destPoolName': 'fake_pool'}
        mock_rest.assert_called_once_with(method='snapshot/volume/clone',
                                          params=params,
                                          request_type='post')
        if size == 2:
            mock_ev.assert_called_once_with(volume, size)

    def test_create_volume_from_snapshot_fail(self):
        volume = fake_volume.fake_volume_obj(self._ctxt)
        snapshot = fake_snapshot.fake_snapshot_obj(self._ctxt, volume_size=10)
        self.assertRaises(
            exception.InvalidInput,
            self.as13000_san.create_volume_from_snapshot, volume, snapshot)

    @ddt.data(1, 2)
    def test_create_cloned_volume(self, size):
        volume = fake_volume.fake_volume_obj(self._ctxt, size=size)
        volume_src = fake_volume.fake_volume_obj(self._ctxt)
        mock_eh = self.mock_object(volume_utils,
                                   'extract_host',
                                   mock.Mock(return_value='fake_pool'))
        mock_tnd = self.mock_object(
            self.as13000_san, '_trans_name_down', mock.Mock(
                side_effect=('fake_name1', 'fake_name2')))
        mock_rest = self.mock_object(as13000_driver.RestAPIExecutor,
                                     'send_rest_api',
                                     mock.Mock())
        mock_ev = self.mock_object(self.as13000_san,
                                   'extend_volume',
                                   mock.Mock())
        self.as13000_san.create_cloned_volume(volume, volume_src)
        mock_eh.assert_called()
        mock_tnd.assert_called()
        method = 'block/lvm/clone'
        params = {
            'srcVolumeName': 'fake_name2',
            'srcPoolName': 'fake_pool',
            'destVolumeName': 'fake_name1',
            'destPoolName': 'fake_pool'}
        request_type = 'post'
        mock_rest.assert_called_once_with(
            method=method, params=params, request_type=request_type)
        if size == 2:
            mock_ev.assert_called_once_with(volume, size)

    def test_create_clone_volume_fail(self):
        volume = fake_volume.fake_volume_obj(self._ctxt)
        volume_source = fake_volume.fake_volume_obj(self._ctxt, size=2)
        self.assertRaises(
            exception.InvalidInput,
            self.as13000_san.create_cloned_volume, volume, volume_source)

    def test_extend_volume(self):
        volume = fake_volume.fake_volume_obj(self._ctxt)
        mock_tnd = self.mock_object(
            self.as13000_san, '_trans_name_down', mock.Mock(
                return_value='fake_name'))
        mock_cv = self.mock_object(self.as13000_san,
                                   '_check_volume',
                                   mock.Mock(return_value=True))
        mock_eh = self.mock_object(volume_utils,
                                   'extract_host',
                                   mock.Mock(return_value='fake_pool'))
        mock_rest = self.mock_object(as13000_driver.RestAPIExecutor,
                                     'send_rest_api',
                                     mock.Mock())
        self.as13000_san.extend_volume(volume, 10)
        mock_tnd.assert_called_once_with(volume.name)
        mock_cv.assert_called_once_with(volume)
        mock_eh.assert_called_once_with(volume.host, level='pool')
        method = 'block/lvm'
        request_type = 'put'
        params = {'pool': 'fake_pool',
                  'name': 'fake_name',
                  'newCapacity': 10240}
        mock_rest.assert_called_once_with(method=method,
                                          request_type=request_type,
                                          params=params)

    def test_extend_volume_fail(self):
        volume = fake_volume.fake_volume_obj(self._ctxt)
        mock_tnd = self.mock_object(
            self.as13000_san, '_trans_name_down', mock.Mock(
                return_value='fake_name'))
        mock_cv = self.mock_object(self.as13000_san,
                                   '_check_volume',
                                   mock.Mock(return_value=False))
        self.assertRaises(exception.VolumeDriverException,
                          self.as13000_san.extend_volume, volume, 10)
        mock_tnd.assert_called_once_with(volume.name)
        mock_cv.assert_called_once_with(volume)

    @ddt.data(True, False)
    def test_delete_volume(self, volume_exist):
        volume = fake_volume.fake_volume_obj(self._ctxt)
        mock_eh = self.mock_object(volume_utils,
                                   'extract_host',
                                   mock.Mock(return_value='fake_pool'))
        mock_tnd = self.mock_object(
            self.as13000_san, '_trans_name_down', mock.Mock(
                return_value='fake_name'))
        mock_cv = self.mock_object(self.as13000_san,
                                   '_check_volume',
                                   mock.Mock(return_value=volume_exist))
        mock_rest = self.mock_object(as13000_driver.RestAPIExecutor,
                                     'send_rest_api',
                                     mock.Mock())
        self.as13000_san.delete_volume(volume)
        mock_eh.assert_called_once_with(volume.host, level='pool')
        mock_tnd.assert_called_once_with(volume.name)
        mock_cv.assert_called_once_with(volume)

        if volume_exist:
            method = 'block/lvm?pool=%s&lvm=%s' % ('fake_pool', 'fake_name')
            request_type = 'delete'
            mock_rest.assert_called_once_with(method=method,
                                              request_type=request_type)

    def test_create_snapshot(self):
        volume = fake_volume.fake_volume_obj(self._ctxt)
        snapshot = fake_snapshot.fake_snapshot_obj(self._ctxt, volume=volume)
        mock_eh = self.mock_object(volume_utils,
                                   'extract_host',
                                   mock.Mock(return_value='fake_pool'))
        mock_cv = self.mock_object(self.as13000_san,
                                   '_check_volume',
                                   mock.Mock(return_value=True))
        mock_tnd = self.mock_object(
            self.as13000_san, '_trans_name_down', mock.Mock(
                side_effect=('fake_name', 'fake_snap')))
        mock_rest = self.mock_object(as13000_driver.RestAPIExecutor,
                                     'send_rest_api',
                                     mock.Mock())
        self.as13000_san.create_snapshot(snapshot)

        mock_eh.assert_called_once_with(volume.host, level='pool')
        mock_tnd.assert_called()
        mock_cv.assert_called_once_with(snapshot.volume)
        method = 'snapshot/volume'
        params = {'snapName': 'fake_snap',
                  'volumeName': 'fake_name',
                  'poolName': 'fake_pool'}
        request_type = 'post'
        mock_rest.assert_called_once_with(method=method,
                                          params=params,
                                          request_type=request_type)

    def test_create_snapshot_fail(self):
        volume = fake_volume.fake_volume_obj(self._ctxt)
        snapshot = fake_snapshot.fake_snapshot_obj(self._ctxt, volume=volume)
        mock_cv = self.mock_object(self.as13000_san,
                                   '_check_volume',
                                   mock.Mock(return_value=False))
        self.assertRaises(exception.VolumeDriverException,
                          self.as13000_san.create_snapshot, snapshot)
        mock_cv.assert_called_once_with(snapshot.volume)

    def test_delete_snapshot(self):
        volume = fake_volume.fake_volume_obj(self._ctxt)
        snapshot = fake_snapshot.fake_snapshot_obj(self._ctxt, volume=volume)
        mock_eh = self.mock_object(volume_utils,
                                   'extract_host',
                                   mock.Mock(return_value='fake_pool'))
        mock_cv = self.mock_object(self.as13000_san,
                                   '_check_volume',
                                   mock.Mock(return_value=True))
        mock_tnd = self.mock_object(
            self.as13000_san, '_trans_name_down', mock.Mock(
                side_effect=('fake_name', 'fake_snap')))
        mock_rest = self.mock_object(as13000_driver.RestAPIExecutor,
                                     'send_rest_api',
                                     mock.Mock())
        self.as13000_san.delete_snapshot(snapshot)

        mock_eh.assert_called_once_with(volume.host, level='pool')
        mock_tnd.assert_called()
        mock_cv.assert_called_once_with(snapshot.volume)
        method = ('snapshot/volume?snapName=%s&volumeName=%s&poolName=%s'
                  % ('fake_snap', 'fake_name', 'fake_pool'))
        request_type = 'delete'
        mock_rest.assert_called_once_with(method=method,
                                          request_type=request_type)

    def test_delete_snapshot_fail(self):
        volume = fake_volume.fake_volume_obj(self._ctxt)
        snapshot = fake_snapshot.fake_snapshot_obj(self._ctxt, volume=volume)
        mock_cv = self.mock_object(self.as13000_san,
                                   '_check_volume',
                                   mock.Mock(return_value=False))
        self.assertRaises(exception.VolumeDriverException,
                          self.as13000_san.delete_snapshot, snapshot)
        mock_cv.assert_called_once_with(snapshot.volume)

    # @ddt.data(['fake_stat',True],
    #           ['fake_stat',False],
    #           ['',True],
    #           ['',False])
    # @ddt.unpack
    # def test_get_volume_stats(self,stats,refresh):
    #     self.as13000_san._stats=stats
    #     mock_uvs=self.mock_object(self.as13000_san, '_update_volume_stats',
    #                               mock.Mock())

    @ddt.data((time.time() - 3000), (time.time() - 4000))
    def test__update_volume_stats(self, time_token):
        self.as13000_san.VENDOR = 'INSPUR'
        self.as13000_san.VERSION = 'V1.3.1'
        self.as13000_san.PROTOCOL = 'iSCSI'
        mock_sg = self.mock_object(configuration.Configuration, 'safe_get',
                                   mock.Mock(return_value='fake_backend_name'))
        fake_pool_backend = [{'pool_name': 'fake_pool'},
                             {'pool_name': 'fake_pool1'}]
        self.as13000_san.pools = ['fake_pool']
        mock_gps = self.mock_object(self.as13000_san, '_get_pools_stats',
                                    mock.Mock(return_value=fake_pool_backend))
        self.as13000_san._stats = None
        self.as13000_san._token_time = time_token
        self.as13000_san.token_available_time = 3600
        mock_rt = self.mock_object(as13000_driver.RestAPIExecutor,
                                   'refresh_token')

        self.as13000_san._update_volume_stats()
        backend_data = {'driver_version': 'V1.3.1',
                        'pools': [{'pool_name': 'fake_pool'}],
                        'storage_protocol': 'iSCSI',
                        'vendor_name': 'INSPUR',
                        'volume_backend_name': 'fake_backend_name'}

        self.assertEqual(backend_data, self.as13000_san._stats)
        mock_sg.assert_called_once_with('volume_backend_name')
        mock_gps.assert_called_once()
        if (time.time() - time_token) > 3600:
            mock_rt.assert_called_once()
        else:
            mock_rt.assert_not_called()

    @ddt.data((True, True, True),
              (True, True, False),
              (False, True, True),
              (False, True, False),
              (False, False, True),
              (False, False, False),
              (True, False, True),
              (True, False, False))
    @ddt.unpack
    def test_initialize_connection(self, host_exist, multipath, chap_enabled):
        volume = fake_volume.fake_volume_obj(self._ctxt)
        connector = {'multipath': multipath,
                     'ip': 'fake_ip',
                     'host': 'fake_host'}
        self.as13000_san.configuration.as13000_chap_enabled = chap_enabled
        fakenode = [{'name': 'fake_name1', 'ip': 'node_ip1'},
                    {'name': 'fake_name2', 'ip': 'node_ip2'},
                    {'name': 'fake_name3', 'ip': 'node_ip3'}]
        self.as13000_san.nodes = fakenode
        if multipath:
            mock_gtfc = self.mock_object(
                self.as13000_san,
                '_get_target_from_conn',
                mock.Mock(return_value=(host_exist,
                                        'target_name',
                                        ['fake_name1', 'fake_name2'])))
        else:
            mock_gtfc = self.mock_object(
                self.as13000_san,
                '_get_target_from_conn',
                mock.Mock(return_value=(host_exist,
                                        'target_name',
                                        ['fake_name1'])))

        mock_altt = self.mock_object(self.as13000_san,
                                     '_add_lun_to_target',
                                     mock.Mock())
        mock_ct = self.mock_object(self.as13000_san,
                                   '_create_target',
                                   mock.Mock())
        mock_ahtt = self.mock_object(self.as13000_san,
                                     '_add_host_to_target',
                                     mock.Mock())
        mock_actt = self.mock_object(self.as13000_san,
                                     '_add_chap_to_target',
                                     mock.Mock())
        mock_gli = self.mock_object(self.as13000_san,
                                    '_get_lun_id',
                                    mock.Mock(return_value='fake_id'))
        mock_rr = self.mock_object(random, 'randint',
                                   mock.Mock(return_value='12345678'))
        connect_info = self.as13000_san.initialize_connection(
            volume, connector)

        if host_exist:
            if multipath:
                target_name = ['target_name', 'target_name']
                portal = ['node_ip1:3260', 'node_ip2:3260']
            else:
                target_name = 'target_name'
                portal = 'node_ip1:3260'
        else:
            target_name = 'target.inspur.fake_host-12345678'
            portal = '%s:3260' % fakenode[2]['ip']
        if multipath and host_exist is False:
            connection_data = {
                'target_discovered': True,
                'volume_id': volume.id,
                'target_portals': [
                    'node_ip1:3260',
                    'node_ip2:3260',
                    'node_ip3:3260'],
                'target_luns': ['fake_id'] * 3,
                'target_iqns': [target_name] * 3}
        elif multipath and host_exist is True:
            connection_data = {
                'target_discovered': True,
                'volume_id': volume.id,
                'target_portals': [
                    'node_ip1:3260',
                    'node_ip2:3260', ],
                'target_luns': ['fake_id'] * 2,
                'target_iqns': target_name}
        else:
            connection_data = {
                'target_discovered': True,
                'volume_id': volume.id,
                'target_portal': portal,
                'target_lun': 'fake_id',
                'target_iqn': target_name
            }
        if chap_enabled:
            connection_data['auth_method'] = 'CHAP'
            connection_data['auth_username'] = 'fakeuser'
            connection_data['auth_password'] = 'fakepass'

        expect_datas = {
            'driver_volume_type': 'iscsi',
            'data': connection_data
        }

        self.assertEqual(expect_datas, connect_info)
        mock_gtfc.assert_called_once_with('fake_ip')
        mock_altt.assert_called_once()
        if not host_exist:
            mock_ct.assert_called_once()
            mock_ahtt.assert_called_once()
            mock_rr.assert_called_once()
            if chap_enabled:
                mock_actt.assert_called_once()

        mock_gli.assert_called_once()

    @ddt.data(True,False)
    def test_terminate_connection(self,delete_target):
        volume = fake_volume.fake_volume_obj(self._ctxt, host='fakehost')
        connector = {'multipath': False,
                     'ip': 'fake_ip',
                     'host': 'fake_host'}
        mock_gtfc = self.mock_object(
            self.as13000_san, '_get_target_from_conn', mock.Mock(
                return_value=('fake_value', 'target_name', 'fake_node')))
        mock_gli = self.mock_object(self.as13000_san,
                                    '_get_lun_id',
                                    mock.Mock(return_value='fake_id'))
        mock_dlft = self.mock_object(self.as13000_san,
                                     '_delete_lun_from_target',
                                     mock.Mock())
        if delete_target:
            mock_gll = self.mock_object(self.as13000_san, '_get_lun_list',
                                        mock.Mock(return_value=[]))
        else:
            mock_gll = self.mock_object(self.as13000_san, '_get_lun_list',
                                        mock.Mock(return_value=[1,2]))
        mock_dt = self.mock_object(self.as13000_san,'_delete_target',
                                   mock.Mock())
        self.as13000_san.terminate_connection(volume,connector)
        mock_gtfc.assert_called_once_with('fake_ip')
        mock_gli.assert_called_once_with(volume,'target_name')
        mock_dlft.assert_called_once_with(lun_id='fake_id',
                                          target_name='target_name')
        mock_gll.assert_called_once_with('target_name')
        if delete_target:
            mock_dt.assert_called_once_with('target_name')
        else:
            mock_dt.assert_not_called()

    def test__get_pools_stats(self):
        pool_date = {}
        mock_rest = self.mock_object(as13000_driver.RestAPIExecutor,
                                     'send_rest_api',
                                     mock.Mock(return_value=pool_date))

