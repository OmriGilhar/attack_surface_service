from typing import Union
from functools import lru_cache

from .entity import Entity
from .virtual_machine import VirtualMachine
from .firewall_rule import FirewallRule


class CloudEnv:
    def __init__(self, details: dict[str, list]) -> None:
        """
        Initiate the Cloud

        :param details: A dictionary of all the cloud details including a
            list of Virtual environment and a list of Firewall rules.
        :type details: dict[str, list]
        """
        self._vms: list[VirtualMachine] = []
        self._fw_rules: list[FirewallRule] = []
        self._init_vms(details.get('vms', None))
        self._init_fw(details.get('fw_rules', None))

    def __contains__(self, vm_id):
        return any(filter(lambda vm: vm.id == vm_id, self._vms))

    def _init_vms(self, vms: list[dict]):
        """
        Loads a list of virtual environment dictionaries to adapt into a
        VirtualMachine instances inside the Cloud dedicated storage.

        dict format:

        * vm_id: VM ID

        * name: VM name

        * tags: list of VM tags (optional)

        :param vms: list of dictionaries to adapt as an VirtualMachine
        instance.
        :type vms: list[dict]
        :return: None
        """
        list(map(
            lambda vm: self._add_vm(
                VirtualMachine(
                    id=vm.get('vm_id', None),
                    name=vm.get('name', None),
                    tags=vm.get('tags', [])
                )
            ),
            vms
        )) if vms else None

    def _init_fw(self, fw_rules: list[dict]):
        """
        Loads a list of firewall rules dictionaries in to a FirewallsRule
        instances inside the Cloud dedicated storage.


        dict format:

        * fw_id: Firewall rule ID

        * source_tag: Source tag

        * dest_tag: Destination tag

        :param fw_rules: list of dictionaries to adapt as an FirewallRule
        instance.
        :type fw_rules: list[dict]
        :return: None
        """
        list(map(
            lambda fw_rule: self._add_fw(
                FirewallRule(
                    id=fw_rule.get('fw_id', None),
                    source_tag=fw_rule.get('source_tag', None),
                    dest_tag=fw_rule.get('dest_tag', None)
                )
            ),
            fw_rules
        )) if fw_rules else None

    def _add_vm(self, vm: VirtualMachine) -> None:
        """
        Adds a VirtualMachine to the cloud virtual machines storage

        :param vm: The virtual machine you wish to add to the cloud storage
        :return: None
        """
        self._vms.append(vm) if not self._validate_unique(
            self._vms,
            vm
        ) else None

    def _add_fw(self, fw: FirewallRule) -> None:
        """
        Adds a FirewallRule to the cloud firewall rules storage

        :param fw: The firewall rule you wish to add to the cloud storage
        :type fw: FirewallRule
        :return: None
        """
        self._fw_rules.append(fw) if not self._validate_unique(
            self._fw_rules, fw
        ) else None

    @lru_cache(maxsize=64)
    def _get_vm_by_id(self, vm_id: str) -> Union[VirtualMachine, None]:
        """
        Get a VM instance by the VM ID, by using LRU Cache we can save time
        for multiple invocation.

        :param vm_id: The ID of the requested VM.
        :type vm_id: str
        :return: A VM instnace if exists, otherwise, returns None.
        :rtype: Union[VirtualMachine, None]
        """
        try:
            return list(filter(lambda vm: vm.id == vm_id, self._vms))[0]
        except IndexError:
            return None

    @staticmethod
    def _validate_unique(store: list[Entity], item: Entity):
        """
        Check if the item do not exists in the store by comparing IDs.

        :param store: The store that contain all the items.
        :type store: list[Entity]
        :param item: The item to check if exists in the store.
        :type item: Entity
        :return: True if the item unique, otherwise, False.
        :rtype: bool
        """
        return any(filter(lambda i: i.id == item.id, store))

    def get_potential_attacks(self, vm_id: str) -> list:
        """
        Search for the attack surface of a given VM ID by cross correlating
        tags.

        :param vm_id: The ID of the VM you wish to get the attack surface of.
        :type vm_id: str
        :return: empty list if VM ID doesn't exists, otherwise, return the
        attack surface of the given VM.
        :rtype: list
        """
        # Check if VM ID exist in the VMs storage.
        if vm_id not in self:
            return []
        candidate_vm = self._get_vm_by_id(vm_id)
        candidate_tags = candidate_vm.tags
        if not candidate_tags:
            return []

        attacking_vms = set()
        # Get the potential attackers tags from by cross correlating firewalls
        # destinations with the candidate VM tags, then get the firewalls
        # source tags, thus, the attackers tags.
        attacking_tags = list(map(lambda fw: fw.source_tag, list(
            filter(lambda fw: fw.dest_tag in candidate_tags, self._fw_rules)
        )))

        # In this section we are searching for the attacker vm, by cross
        # correlating vm tags with attackers tags.
        for tag in attacking_tags:
            attacking_vms |= set([
                vm.id for vm in filter(lambda vm: tag in vm.tags, self._vms)
            ])
        return list(attacking_vms)

    def get_vm_size(self) -> int:
        """
        Get the size of the cloud vm count.

        :return: How many vm are running under the cloud.
        :rtype: int
        """
        return len(self._vms)
