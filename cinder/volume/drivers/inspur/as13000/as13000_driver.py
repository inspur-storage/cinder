# Copyright 2017 Inspur Corp.
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
Volume driver for Inspur AS13000
"""

import functools
import json
import time
import random
import re
import requests

from cinder import exception
# from cinder import interface
from cinder.volume import utils as volume_utils
from cinder.volume.drivers.san import san
from oslo_config import cfg
from oslo_log import log as logging
from oslo_utils import units

LOG = logging.getLogger(__name__)

inspur_as13000_opts = [
    cfg.ListOpt('inspur_as13000_ipsan_pool',
                default=['Pool0'],
                help='The Storage Pool Cinder use.'),
    cfg.IntOpt('as13000_token_available_time',
               default=3600,
               help='The valid period of token.'),
    cfg.IntOpt('as13000_api_port',
               default=8088,
               help='The port that Driver used to send request to the backend.'),
    cfg.BoolOpt('as13000_chap_enabled',
                default=False,
                help='enable chap or not when initialize connection'),
    cfg.StrOpt('as13000_chap_username',
               default='admin',
               help='Chap username the target used'),
    cfg.StrOpt('as13000_chap_password',
               default='admin',
               help='Chap password the target used'),
    cfg.StrOpt('as13000_mete_pool',
               default='',
               help='mete_pool as13000 used'),
    cfg.IntOpt('as13000_data_pool_type',
               default=1,
               help='type of as13000 pool')
]

CONF = cfg.CONF
CONF.register_opts(inspur_as13000_opts)


def inspur_driver_debug_trace(f):
    """Log the method entrance and exit including active backend name.
    This should only be used on VolumeDriver class methods. It depends on
    having a 'self' argument that is a AS13000_Driver.
    """

    @functools.wraps(f)
    def wrapper(*args, **kwargs):
        driver = args[0]  # self
        cls_name = driver.__class__.__name__
        method_name = "%(cls_name)s.%(method)s" % {"cls_name": cls_name,
                                                   "method": f.__name__}
        # backend_name = driver._update_volume_stats.get('volume_backend_name')
        backend_name = driver.configuration.volume_backend_name
        LOG.debug("[%(backend_name)s] Enter %(method_name)s" %
                  {"method_name": method_name, "backend_name": backend_name})
        result = f(*args, **kwargs)
        LOG.debug("[%(backend_name)s] Leave %(method_name)s" %
                  {"method_name": method_name, "backend_name": backend_name})
        return result

    return wrapper


class RestAPIExecutor(object):
    def __init__(self, hostname, port, username, password):
        self._hostname = hostname
        self._port = port
        self._username = username
        self._password = password
        self._token_pool = []
        self._token_size = 1

    def logins(self):
        """login the AS13000 and store the token in token_pool"""
        times = self._token_size
        while times > 0:
            token = self.login()
            self._token_pool.append(token)
            times = times - 1
        LOG.debug('Login the AS13000.')

    def login(self):
        """login in the AS13000 and return the token"""
        method = 'security/token'
        params = {'name': self._username, 'password': self._password}
        token = self.send_rest_api(method=method, params=params,
                                   request_type='post').get('token')
        return token

    def logout(self):
        method = 'security/token'
        self.send_rest_api(method=method, request_type='delete')

    def refresh_token(self, force=False):
        if force is True:
            for i in range(self._token_size):
                self._token_pool = []
                token = self.login()
                self._token_pool.append(token)
        else:
            for i in range(self._token_size):
                self.logout()
                token = self.login()
                self._token_pool.append(token)
        LOG.debug('Tokens have been refreshed.')

    def send_rest_api(self, method, params=None, request_type='post'):
        attempts = 3
        msge = ''
        while attempts > 0:
            attempts -= 1
            try:
                return self.send_api(method, params, request_type)
            except exception.VolumeDriverException as e:
                LOG.error(e)
                msge = str(e)
                self.refresh_token(force=True)
                time.sleep(1)
            except exception.VolumeBackendAPIException as e:
                msge = str(e)
                break
        msg = r'Error running RestAPI : /rest/%s ; Error Message: %s' % (
            method, msge)
        LOG.error(msg)
        raise exception.VolumeDriverException(msg)

    def send_api(self, method, params=None, request_type='post'):
        if params is not None:
            params = json.dumps(params)
        url = 'http://%s:%s/%s/%s' % (self._hostname, self._port, 'rest',
                                      method)
        # header is not needed when the driver login the backend
        if method == 'security/token':
            # token won't be return to the token_pool
            if request_type == 'delete':
                header = {'X-Auth-Token': self._token_pool.pop(0)}
            else:
                header = None
        else:
            if len(self._token_pool) == 0:
                self.logins()
            token = self._token_pool.pop(0)
            header = {'X-Auth-Token': token}
            self._token_pool.append(token)

        if request_type == 'post':
            req = requests.post(url,
                                data=params,
                                headers=header)
        elif request_type == 'get':
            req = requests.get(url,
                               data=params,
                               headers=header)
        elif request_type == 'put':
            req = requests.put(url,
                               data=params,
                               headers=header)
        elif request_type == 'delete':
            req = requests.delete(url,
                                  data=params,
                                  headers=header)
        else:
            msg = 'Unsupported request_type: %s' % request_type
            raise exception.VolumeBackendAPIException(msg)

        try:
            response = req.json()
            code = response.get('code')
            if code == 0:
                if request_type == 'get':
                    data = response.get('data')

                else:
                    if method == 'security/token':
                        data = response.get('data')
                    else:
                        data = response.get('message')
                        data = str(data).lower()
                        if hasattr(data, 'success'):
                            return
            elif code == 301:
                msg = 'Token is out time'
                LOG.error(msg)
                raise exception.VolumeDriverException(msg)
            else:
                message = response.get('message')
                msg = ('The RestAPI exception output:'
                       'Message:%s, Code:%s' % (message, code))
                LOG.error(msg)
                raise exception.VolumeBackendAPIException(msg)

        except ValueError:
            response = 'No Response from backend'
            data = None
        req.close()

        req_code = req.status_code
        if req_code != 200:
            msg = 'Request code: %s API response: %s' % (req_code, response)
            LOG.error(msg)
            raise exception.VolumeDriverException(msg)
        return data


#@interface.volumedriver
class AS13000Driver(san.SanISCSIDriver):
    """AS13000 Volume Driver
    Version history:
    1.0 - Initial driver

    """

    VENDOR = 'INSPUR'
    VERSION = '1.0.0'
    PROTOCOL = 'iSCSI'

    def __init__(self, *args, **kwargs):
        super(AS13000Driver, self).__init__(*args, **kwargs)
        self.configuration.append_config_values(inspur_as13000_opts)
        self.hostname = self.configuration.san_ip
        self.port = self.configuration.as13000_api_port
        self.username = self.configuration.san_login
        self.password = self.configuration.san_password
        self.token_available_time = (self.configuration.
                                     as13000_token_available_time)
        self.data_pool_type = self.configuration.as13000_data_pool_type
        self.meta_pool = self.configuration.as13000_mete_pool
        self.pools = []
        self.nodes = []
        self._token_time = 0
        # get the RestAPIExecutor
        self._rest = RestAPIExecutor(
            self.hostname,
            self.port,
            self.username,
            self.password)

    @inspur_driver_debug_trace
    def do_setup(self, context):

        # get tokens for Driver
        self._rest.logins()
        self._token_time = time.time()

        # get Available nodes in backend
        for node in self._get_cluster_status():
            if node.get('healthStatus') == 1:
                self.nodes.append(node)

        # self._init_pool_list()
        self.pools = self.configuration.inspur_as13000_ipsan_pool

        # Validate that the pool exists
        self._validate_pools_exist()
        self._check_meta_pool()

    @inspur_driver_debug_trace
    def check_for_setup_error(self):
        # check the required flags in conf
        required_flags = ['san_ip', 'san_login', 'san_password',
                          'inspur_as13000_ipsan_pool']
        for flag in required_flags:
            if not self.configuration.safe_get(flag):
                LOG.error('%s is not set.' % flag)
                raise exception.InvalidInput(reason='%s is not set.' % flag)

        # make sure at least one node can
        if len(self.nodes) == 0:
            msg = "No healthy Node are available !"
            LOG.error(msg)
            raise exception.VolumeDriverException(message=msg)

    @inspur_driver_debug_trace
    def _validate_pools_exist(self):
        """Check the pool in conf exist in the AS13000"""
        pool_backend_names = []
        for pool in self._get_pools_stats():
            pool_backend_names.append(pool.get('pool_name'))
        for pool in self.pools:
            if pool not in pool_backend_names:
                LOG.error('%s is not exist in backend storage.' % pool)
                raise exception.InvalidInput(
                    reason='%s is not exist in backend storage.' % pool)

    def _check_meta_pool(self):
        if self.data_pool_type == 1:
            self.meta_pool = self.pools[0]

    @inspur_driver_debug_trace
    def create_volume(self, volume):
        """create volume in backend """
        pool = volume_utils.extract_host(volume.host, level='pool')
        method = 'block/lvm'
        size = volume.size * 1024
        name = self._trans_name_down(volume.name)
        request_type = "post"
        params = {
            "dataPool": pool,
            "name": name,
            "capacity": size,
            "dataPoolType": self.data_pool_type,
            "metaPool": self.meta_pool}
        self._rest.send_rest_api(method=method, params=params,
                                 request_type=request_type)
        LOG.info('Create volume: volume name:%s, size: %s, pool: %s'
                 % (name, size, pool))

    @inspur_driver_debug_trace
    def create_volume_from_snapshot(self, volume, snapshot):
        if snapshot['volume_size'] > volume.size:
            msg = ("create_volume_from_snapshot: snapshot %(snapshot_name)s "
                   "size is %(snapshot_size)dGB and doesn't fit in target "
                   "volume %(volume_name)s of size %(volume_size)dGB." %
                   {'snapshot_name': snapshot.name,
                    'snapshot_size': snapshot.volume_size,
                    'volume_name': volume.name,
                    'volume_size': volume.size})
            LOG.error(msg)
            raise exception.InvalidInput(message=msg)
        source_vol_name = 'volume_%s' % snapshot.volume_id
        source_vol_name = self._trans_name_down(source_vol_name)
        source_vol = snapshot.volume
        sourc_pool = volume_utils.extract_host(source_vol['host'],
                                               level='pool')
        dest_name = self._trans_name_down(volume.name)
        dest_pool = volume_utils.extract_host(volume.host, level='pool')
        snapshot_name = self._trans_name_down(snapshot.name)
        method = 'snapshot/volume/clone'
        params = {'srcVolumeName': source_vol_name,
                  'srcPoolName': sourc_pool,
                  'snapName': snapshot_name,
                  'destVolumeName': dest_name,
                  'destPoolName': dest_pool}
        request_type = 'post'
        self._rest.send_rest_api(method=method,
                                 params=params,
                                 request_type=request_type)
        if volume.size > source_vol['size']:
            self.extend_volume(volume, volume.size)
        LOG.info('Create volume from snapshot: volume name:%s, size: %s, '
                 'pool: %s, source: %s'
                 % (dest_name, volume.size, dest_pool, source_vol_name))

    @inspur_driver_debug_trace
    def create_cloned_volume(self, volume, src_vref):
        if src_vref.size > volume.size:
            msg = ("create_cloned_volume: source volume %(src_vol)s "
                   "size is %(src_size)dGB and doesn't fit in target "
                   "volume %(tgt_vol)s of size %(tgt_size)dGB." %
                   {'src_vol': src_vref.name,
                    'src_size': src_vref.size,
                    'tgt_vol': volume.name,
                    'tgt_size': volume.size})
            LOG.error(msg)
            raise exception.InvalidInput(message=msg)
        dest_pool = volume_utils.extract_host(volume.host, level='pool')
        src_pool = volume_utils.extract_host(src_vref['host'], level='pool')
        dest_vol_name = self._trans_name_down(volume.name)
        src_vol_name = self._trans_name_down(src_vref.name)
        method = 'block/lvm/clone'
        params = {'srcVolumeName': src_vol_name,
                  'srcPoolName': src_pool,
                  'destVolumeName': dest_vol_name,
                  'destPoolName': dest_pool}
        request_type = 'post'
        self._rest.send_rest_api(method=method,
                                 params=params,
                                 request_type=request_type)

        if volume.size > src_vref.size:
            self.extend_volume(volume, volume.size)
        LOG.info('Create clone volume: volume name:%s, size: %s, '
                 'pool: %s, source: %s'
                 % (dest_vol_name, volume.size, dest_pool, src_vol_name))

    @inspur_driver_debug_trace
    def extend_volume(self, volume, new_size):
        """extend volume to new size"""
        method = 'block/lvm'
        request_type = 'put'
        size = int(new_size) * 1024
        name = self._trans_name_down(volume.name)
        if self._check_volume(volume) is False:
            msg = ('Extend Volume Failed: Volume %s does not exist.'
                   % name)
            LOG.error(msg)
            raise exception.VolumeDriverException(message=msg)
        pool = volume_utils.extract_host(volume.host, level='pool')
        params = {'pool': pool,
                  'name': name,
                  'newCapacity': size}
        self._rest.send_rest_api(method=method,
                                 params=params,
                                 request_type=request_type)
        LOG.info('Extend the volume(%s) size from %s GB to %s GB'
                 % (volume.name, volume.size, new_size))

    @inspur_driver_debug_trace
    def delete_volume(self, volume):
        """Delete volume from AS13000 """
        pool = volume_utils.extract_host(volume.host, level='pool')
        name = self._trans_name_down(volume.name)
        method = 'block/lvm?pool=%s&lvm=%s' % (pool, name)
        request_type = 'delete'
        if self._check_volume(volume):
            self._rest.send_rest_api(method=method,
                                     request_type=request_type)
            LOG.info('delete volume %s' % name)
        else:
            # if volume is not exist in backend ,the driver will do
            # nothing but log it
            LOG.info('Tried to delete non-existent volume %s.' % name)

    @inspur_driver_debug_trace
    def create_snapshot(self, snapshot):
        """create snapshot of volume in backend, the snapshot type of AS13000
         is copy-on-write"""
        source_volume = snapshot.volume
        if self._check_volume(source_volume) is False:
            msg = ('create_snapshot: Source_volume %s does not exist.'
                   % source_volume)
            LOG.error(msg)
            raise exception.VolumeDriverException(message=msg)
        pool = volume_utils.extract_host(source_volume.host, level='pool')
        volume_name = self._trans_name_down(source_volume.name)
        snapshot_name = self._trans_name_down(snapshot.name)
        method = 'snapshot/volume'
        params = {'snapName': snapshot_name,
                  'volumeName': volume_name,
                  'poolName': pool}
        request_type = 'post'
        self._rest.send_rest_api(method=method, params=params,
                                 request_type=request_type)
        LOG.info('create snapshot %s from volume %s' % (snapshot_name,
                                                        volume_name))

    @inspur_driver_debug_trace
    def delete_snapshot(self, snapshot):
        """Delete snapshot of volume."""
        source_volume = snapshot.volume
        if self._check_volume(source_volume) is False:
            msg = ('delete_snapshot: Source_volume %s does not exist.'
                   % source_volume)
            LOG.error(msg)
            raise exception.VolumeDriverException(message=msg)
        pool = volume_utils.extract_host(source_volume.host, level='pool')
        volume_name = self._trans_name_down(source_volume.name)
        snapshot_name = self._trans_name_down(snapshot.name)
        method = ('snapshot/volume?snapName=%s&volumeName=%s&poolName=%s'
                  % (snapshot_name, volume_name, pool))
        request_type = 'delete'
        self._rest.send_rest_api(method=method, request_type=request_type)
        LOG.info('delete snapshot %s of volume %s !'
                 % (snapshot_name, volume_name))

    @inspur_driver_debug_trace
    def get_volume_stats(self, refresh=False):
        """Get volume stats.
        If we haven't gotten stats yet or 'refresh' is True,
        run update the stats first. """
        if not self._stats or refresh:
            self._update_volume_stats()
        return self._stats

    @inspur_driver_debug_trace
    def _update_volume_stats(self):
        """update the backend stats including driver info and pools info"""
        data = {}
        backend_name = self.configuration.safe_get('volume_backend_name')
        data['vendor_name'] = self.VENDOR
        data['driver_version'] = self.VERSION
        data['storage_protocol'] = self.PROTOCOL
        data['volume_backend_name'] = backend_name
        pools_in_backend = self._get_pools_stats()
        pools = []
        # AS13000 only return all the pools info, so the driver gets all the
        # pools info, and filter out pools the driver used
        for pool in self.pools:
            for pool_b in pools_in_backend:
                if pool == pool_b.get('pool_name'):
                    pools.append(pool_b)
        data['pools'] = pools
        self._stats = data

        # Driver excute this method every minute, so we set this when the
        # _update_volume_stats excute for times ,the driver will refresh
        # the token
        time_difference = time.time() - self._token_time
        if time_difference > self.token_available_time:
            self._rest.refresh_token()
            self._token_time = time.time()
            LOG.debug('Token of Driver has been refreshed')
        LOG.info('Update volume stats : %s' % self._stats)

    @inspur_driver_debug_trace
    def initialize_connection(self, volume, connector, **kwargs):
        """1.check if the host exist in targets
           2.1 if there is target that has the host,add the volume to the target
           2.2 if not: create an target add host to host add volume to host
           3 return the target info
           """
        host_ip = connector['ip']
        portal = None
        chap_enabled = self.configuration.as13000_chap_enabled
        multipath = connector.get("multipath", False)
        # Check if there host exist in targets
        host_exist, target_name, node_of_target = self._get_target_from_conn(
            host_ip)
        if host_exist:
            # host exist just need add lun to the exist target
            self._add_lun_to_target(target_name=target_name, volume=volume)

        else:
            # host doesn't exist,
            # create target in node,
            # add host to target add lun to target.
            if multipath:
                #node = self.nodes
                node_of_target = [node['name']
                                  for node in self.nodes]
                nodes = ','.join(node_of_target)
                target_name = (
                    'target.inspur.%s-%s' %
                    (connector['host'], str(
                        random.randint(
                            0, 99999999)).zfill(8)))
                self._create_target(target_node=nodes,
                                    target_name=target_name)
            else:
                # single node
                preferred_node = self.nodes.pop(0)
                self.nodes.append(preferred_node)
                node_of_target = [preferred_node.get('name')]
                target_name = (
                    'target.inspur.%s-%s' %
                    (connector['host'], str(
                        random.randint(
                            0, 99999999)).zfill(8)))
                self._create_target(target_node=node_of_target[0],
                                    target_name=target_name)

            self._add_host_to_target(host_ip=host_ip,
                                     target_name=target_name)
            self._add_lun_to_target(target_name=target_name, volume=volume)
            if chap_enabled:
                self._add_chap_to_target(target_name,
                                         self.configuration.chap_username,
                                         self.configuration.chap_password)

        if multipath:
            portal = []
            cluster = self.nodes
            for node_back in cluster:
                if node_back['name'] in node_of_target:
                    portal.append('%s:%s' % (node_back.get('ip'), '3260'))
            lun_id = self._get_lun_id(volume, target_name)
            connection_data = {
                'target_discovered': True,
                'volume_id': volume.id,
                'target_portals': portal,
                'target_luns': [lun_id] * len(portal),
                'target_iqns': [target_name] * len(portal)
            }

        else:
            # single node
            cluster = self.nodes
            for node_back in cluster:
                if node_back.get('name') == node_of_target[0]:
                    portal = '%s:%s' % (node_back.get('ip'), '3260')
                    break
            lun_id = self._get_lun_id(volume, target_name)
            connection_data = {
                'target_discovered': True,
                'volume_id': volume.id,
                'target_portal': portal,
                'target_lun': lun_id,
                'target_iqn': target_name
            }
        if chap_enabled:
            connection_data['auth_method'] = 'CHAP'
            connection_data['auth_username'] = self.configuration.chap_username
            connection_data['auth_password'] = self.configuration.chap_password
        datas = {
            'driver_volume_type': 'iscsi',
            'data': connection_data
        }
        LOG.info('initialize_connection: %s' % datas)
        return datas

    @inspur_driver_debug_trace
    def terminate_connection(self, volume, connector, **kwargs):
        """delete lun from target,
           if target has no any lun, driver will delete the target"""
        volume_name = self._trans_name_down(volume.name)
        if connector['ip']:
            host_ip = connector['ip']
            # host, target_name, node_name = self._get_target_from_conn(host_ip)
            # lun_id = self._get_lun_id(volume, target_name)
            target_list = self._get_target_list()
            for target in target_list:
                if host_ip in target['hostIp']:
                    for lun in target_list['lun']:
                        if volume_name == lun['lvm']:
                            lun_id = lun['lunID']
                            break
                    if lun_id is not None:
                        break
        else:
            target_list = self._get_target_list()
            for target in target_list:
                for lun in target_list['lun']:
                    if volume_name == lun['lvm']:
                        target_name = target['name']
                        lun_id = lun['lunID']
                        break
                if lun_id is not None:
                    break
        self._delete_lun_from_target(target_name=target_name,
                                     lun_id=lun_id)
        luns = self._get_lun_list(target_name)
        if len(luns) == 0:
            self._delete_target(target_name)
        LOG.info('terminate_connection: volume %s with connector %s'
                 % (volume.id, connector))

    @inspur_driver_debug_trace
    def _get_pools_stats(self):
        # get /rest/block/pool
        method = 'block/pool?type=2'
        requests_type = 'get'
        pool_data = self._rest.send_rest_api(method=method,
                                             request_type=requests_type)
        LOG.debug('pools in backs %s' % pool_data)
        pools = []
        for pool in pool_data:
            if pool.get('name') in self.pools:
                total_capacity = pool.get('totalCapacity')
                total_capacity_gb = self._unit_convert(total_capacity)
                used_capacity = pool.get('usedCapacity')
                used_capacity_gb = self._unit_convert(used_capacity)
                free_capacity_gb = total_capacity_gb - used_capacity_gb
                new_pool = {
                    'pool_name': pool.get('name'),
                    'pool_id': pool.get('ID'),
                    'total_capacity_gb': total_capacity_gb,
                    'free_capacity_gb': free_capacity_gb,
                    'thin_provisioning_support': True,
                    'thick_provisioning_support': False,
                }
                pools.append(new_pool)
        return pools

    @inspur_driver_debug_trace
    def _get_target_from_conn(self, host_ip):
        host_exist = False
        target_name = None
        node = None
        target_list = self._get_target_list()
        for target in target_list:
            if host_ip in target['hostIp']:
                host_exist = True
                target_name = target['name']
                node = target['node']
                break
        return host_exist, target_name, node

    @inspur_driver_debug_trace
    def _get_target_list(self):
        """get a list of all targets in backend"""
        method = 'block/target/detail'
        request_type = 'get'
        data = self._rest.send_rest_api(method=method,
                                        request_type=request_type)
        LOG.debug("get all the target in backend : %s" % data)
        return data

    @inspur_driver_debug_trace
    def _get_host_from_target(self, target_name):
        """get host list from the specified target"""
        method = 'block/host?name=%s' % target_name
        request_type = 'get'
        hosts = self._rest.send_rest_api(method=method,
                                         request_type=request_type)
        return hosts

    @inspur_driver_debug_trace
    def _create_target(self, target_name, target_node):
        """create a target on the specified node"""
        method = 'block/target'
        params = {'name': target_name, 'nodeName': target_node}
        request_type = 'post'
        self._rest.send_rest_api(method=method,
                                 params=params,
                                 request_type=request_type)

    @inspur_driver_debug_trace
    def _delete_target(self, target_name):
        """delete all target of all the node"""
        method = 'block/target?name=%s' % target_name
        request_type = 'delete'
        self._rest.send_rest_api(method=method,
                                 request_type=request_type)
        LOG.debug('Delete target:%s' % target_name)

    @inspur_driver_debug_trace
    def _add_chap_to_target(self, target_name, chap_username, chap_password):
        """add CHAP to Target """
        method = 'block/chap/chap/bond'
        params = {'target': target_name,
                  'user': chap_username,
                  'password': chap_password}
        request_type = 'post'
        self._rest.send_rest_api(method=method,
                                 params=params,
                                 request_type=request_type)
        LOG.debug('add CHAP to Target')

    @inspur_driver_debug_trace
    def _add_host_to_target(self, host_ip, target_name):
        """add the authority of Host to target"""
        method = 'block/host'
        params = {'name': target_name, 'hostIp': host_ip}
        request_type = 'post'
        self._rest.send_rest_api(method=method,
                                 params=params,
                                 request_type=request_type)
        LOG.debug('add Host:%s to Target:%s' % (host_ip, target_name))

    @inspur_driver_debug_trace
    def _add_lun_to_target(self, target_name, volume):
        """add volume to target"""
        pool = volume_utils.extract_host(volume.host, level='pool')
        volume_name = self._trans_name_down(volume.name)
        method = 'block/lun'
        params = {'name': target_name,
                  'pool': pool,
                  'lvm': volume_name}
        request_type = 'post'
        self._rest.send_rest_api(method=method,
                                 params=params,
                                 request_type=request_type)
        LOG.debug('add lun:%s in pool %s to target:%s'
                  % (volume.name, pool, target_name))

    @inspur_driver_debug_trace
    def _delete_lun_from_target(self, target_name, lun_id):
        """delete lun from target_name"""
        method = 'block/lun?name=%s&id=%s&force=1' % (target_name, lun_id)
        request_type = 'delete'
        self._rest.send_rest_api(method=method, request_type=request_type)
        LOG.debug('Delete lun:%s from target:%s' % (lun_id, target_name))

    @inspur_driver_debug_trace
    def _get_lun_list(self, target_name):
        """get all lun list of the target"""
        method = 'block/lun?name=%s' % target_name
        request_type = 'get'
        lun_list = self._rest.send_rest_api(method=method,
                                            request_type=request_type)
        return lun_list

    @inspur_driver_debug_trace
    def _check_volume(self, volume):
        """check if the volume exists in the backend"""
        pool = volume_utils.extract_host(volume.host, 'pool')
        volume_name = self._trans_name_down(volume.name)
        attempts = 3
        while attempts > 0:
            volumes = self._get_volumes(pool)
            attempts -= 1
            for vol in volumes:
                if volume_name == vol.get('name'):
                    return True
            time.sleep(5)
        return False

    @inspur_driver_debug_trace
    def _get_volumes(self, pool):
        """get all the volumes in the pool"""
        method = 'block/lvm?pool=%s' % pool
        request_type = 'get'
        volumes = self._rest.send_rest_api(method=method,
                                           request_type=request_type)

        return volumes

    @inspur_driver_debug_trace
    def _get_cluster_status(self):
        """get the all nodes of backend """
        method = 'cluster/node'
        request_type = 'get'
        cluster = self._rest.send_rest_api(method=method,
                                           request_type=request_type)
        return cluster

    @inspur_driver_debug_trace
    def _get_lun_id(self, volume, target_name):
        """get lun id of voluem in target"""
        pool = volume_utils.extract_host(volume.host, level='pool')
        lun_id = None
        luns = self._get_lun_list(target_name)
        volume_name = self._trans_name_down(volume.name)
        for lun in luns:
            mappinglvm = lun.get('mappingLvm')
            lun_name = mappinglvm.replace(r'%s/' % pool, '')
            if lun_name == volume_name:
                lun_id = lun.get('id')
        return lun_id

    @inspur_driver_debug_trace
    def _trans_name_down(self, name):
        """Legitimize the name,because AS13000 volume name is
        only allowed letters,numbers,_ """
        down_name = name.replace('-', '_')
        return down_name

    @inspur_driver_debug_trace
    def _unit_convert(self, capacity):
        """Convert all units to GB"""
        capacity = str(capacity)
        capacity = capacity.upper()
        try:
            unit_of_used = re.findall(r'[A-Z]', capacity)
            unit_of_used = ''.join(unit_of_used)
        except BaseException:
            unit_of_used = ''
        capacity = capacity.replace(unit_of_used, '')
        capacity = float(capacity.replace(unit_of_used, ''))
        if unit_of_used in ['B', '']:
            capacity = capacity / units.Gi
        elif unit_of_used in ['K', 'KB']:
            capacity = capacity / units.Mi
        elif unit_of_used in ['M', 'MB']:
            capacity = capacity / units.Ki
        elif unit_of_used in ['G', 'GB']:
            capacity = capacity
        elif unit_of_used in ['T', 'TB']:
            capacity = capacity * units.Ki
        elif unit_of_used in ['E', 'EB']:
            capacity = capacity * units.Mi

        capacity = '%.0f' % capacity
        return float(capacity)
