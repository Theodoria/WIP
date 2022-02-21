"""Index analyzer plugin for SEKOIA.IO indicators."""
from __future__ import unicode_literals

import logging
from functools import lru_cache
from ipaddress import ip_address
import requests
from flask import current_app

from timesketch.lib.analyzers import interface
from timesketch.lib.analyzers import manager
from timesketch.lib import emojis

logger = logging.getLogger('timesketch.analyzers.sekoia_io')


class SekoiaIOIndicators(interface.BaseAnalyzer):
    """Analyzer for SEKOIA.IO indicators."""

    NAME = 'sekoia_io'
    DISPLAY_NAME = 'SEKOIA.IO indicators'
    DESCRIPTION = 'Mark events using SEKOIA.IO intel indicators'

    DEPENDENCIES = frozenset(['domain'])

    def __init__(self, index_name, sketch_id, timeline_id=None, **kwargs):
        """Initialize the Analyzer.
        Args:
            index_name: Elasticsearch index name
            sketch_id: The ID of the sketch.
            timeline_id: The ID of the timeline.
        """
        self.index_name = index_name
        indicator = kwargs.get('indicator')
        self.indicator_type = indicator.get('type')
        self.fields_query = indicator.get('fields')
        self.search_query = str()
        for field in self.fields_query:
            if field == self.fields_query[0]:
                self.search_query = "{}:*".format(field)
            else:
                self.search_query += " OR {}:*".format(field)
        super().__init__(index_name, sketch_id, timeline_id=timeline_id)
        self.sekoiaio_domain = current_app.config.get('SEKOIAIO_DOMAIN', "api.sekoia.io")
        self.sekoiaio_api_key = current_app.config.get('SEKOIAIO_API_KEY')

    @lru_cache
    def find_indicator(self, indicator_value):
        """Populates the intel attribute with entities from SEKOIA.IO."""
        if (not indicator_value) or self.indicator_stops(indicator_value):
            return list()
        results = requests.get(
            'https://' + self.sekoiaio_domain + '/v2/inthreat/indicators',
            params={'value': indicator_value, 'type': self.indicator_type},
            headers={'Authorization': 'Bearer {}'.format(self.sekoiaio_api_key)}
        )
        if results.status_code != 200:
            return list()
        else:
            return results.json()['items']

    def mark_event(self, event, api_result):
        """Anotate an event with data from indicators and neighbors.
        Tags with skull emoji, adds a comment to the event.
        """
        event.add_emojis([emojis.get_emoji('SKULL')])
        tags = ["SEKOIA.IO", "threat-intelligence"]
        for phase in api_result['kill_chain_phases']:
            tags.append("{}:{}".format(phase['kill_chain_name'], phase['phase_name']))
        for itype in api_result['indicator_types']:
            tags.append('indicator_type:{}'.format(itype))
        if api_result['revoked']:
            tags.append('indicator_revoked')
        event.add_tags(tags)
        event.add_comment("Link to the indicator: https://{}/intelligence/objects/{}".format(self.sekoiaio_domain, api_result["id"]))
        event.commit()

    def run(self):
        """Entry point for the analyzer.
        Returns:
            String with summary of the analyzer result
        """
        if not self.sekoiaio_domain or not self.sekoiaio_api_key:
            return 'No SEKOIA.IO configuration settings found, aborting.'

        events = self.event_stream(query_string=self.search_query,
                                   return_fields=self.fields_query)
        total_matches = 0
        matching_indicators = set()
        for event in events:
            indicator_value = None
            for k in self.fields_query:
                try:
                    indicator_value = event.source.get(k)
                    api_result = self.find_indicator(indicator_value)
                    if len(api_result) > 0:
                        total_matches += 1
                        matching_indicators.add(event)
                        self.mark_event(event, api_result[0])
                        break
                except:
                    continue

        if not total_matches:
            return 'No indicator of type {} has been found in the timeline.'.format(self.indicator_type)
        return '{} events matched {} indicators of type {}.'.format(total_matches, len(matching_indicators), self.indicator_type)


    @staticmethod
    def get_kwargs():
        """Returns an array of indicator type of Timesketch.
        Returns:
            list of dict representing indicator types associated to a list of fields
        """
        return [
            {'indicator':{ 'type': 'file', 'fields': ['SHA1', 'file_hash_sha1', 'file_hash_sha256', 'SHA256', 'file_hash_md5', 'MD5']}},
        ]
from get_kwargs('indicators')
