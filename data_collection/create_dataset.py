import argparse
import contextlib
import json
import os
import subprocess
import traceback
import logging

import pandas as pd
import wget
#from . import graphql
#from .utils import safe_mkdir

from pathlib import Path
from urllib.parse import urlparse
from git2json import *
from datetime import datetime
import contextlib
import os
#safemkdir start
def safe_mkdir(dirname):
    with contextlib.suppress(FileExistsError):
        os.mkdir(dirname)
        #safemkdir end
#Graphql
import csv
import itertools
import logging
import time

import collections

import requests
import os

#from .utils import safe_mkdir


class RepoNotFoundError(BaseException):
    pass


less_than_10_vulns = [
    '01org_opa-ff', '01org_opa-fm', '01org_tpm2.0-tools',
    '10gen-archive_mongo-c-driver-legacy', '1up-lab_oneupuploaderbundle',
    '389ds_389-ds-base', '3s3s_opentrade', '94fzb_zrlog', 'aaron-junker_usoc',
    'aaugustin_websockets', 'aawc_unrar', 'abcprintf_upload-image-with-ajax',
    'abhinavsingh_proxy.py', 'absolunet_kafe', 'acassen_keepalived',
    'accel-ppp_accel-ppp', 'accenture_mercury', 'acinq_eclair',
    'acossette_pillow', 'acpica_acpica', 'actions_http-client',
    'adaltas_node-csv-parse', 'adaltas_node-mixme', 'adamghill_django-unicorn',
    'adamhathcock_sharpcompress', 'adaptivecomputing_torque',
    'admidio_admidio', 'adodb_adodb', 'adrienverge_openfortivpn',
    'advancedforms_advanced-forms', 'afarkas_lazysizes', 'ahdinosaur_set-in',
    'aheckmann_mpath', 'aheckmann_mquery', 'aimhubio_aim', 'aio-libs_aiohttp',
    'aircrack-ng_aircrack-ng', 'airmail_airmailplugin-framework',
    'airsonic_airsonic', 'ai_nanoid', 'akashrajpurohit_clipper',
    'akheron_jansson', 'akimd_bison', 'akrennmair_newsbeuter',
    'alanaktion_phproject', 'alandekok_freeradius-server', 'alanxz_rabbitmq-c',
    'albertobeta_podcastgenerator', 'alerta_alerta', 'alexreisner_geocoder',
    'alex_rply', 'algolia_algoliasearch-helper-js', 'alkacon_apollo-template',
    'alkacon_mercury-template', 'alkacon_opencms-core', 'amazeeio_lagoon',
    'ambiot_amb1_arduino', 'ambiot_amb1_sdk', 'ampache_ampache',
    'amyers634_muracms', 'anchore_anchore-engine', 'andialbrecht_sqlparse',
    'andrerenaud_pdfgen', 'android_platform_bionic', 'andrzuk_finecms',
    'andya_cgi--simple', 'andyrixon_layerbb', 'angus-c_just',
    'ankane_chartkick', 'ansible-collections_community.crypto',
    'ansible_ansible-modules-extras', 'antonkueltz_fastecdsa',
    'antswordproject_antsword', 'anurodhp_monal', 'anymail_django-anymail',
    'aomediacodec_libavif', 'apache_activemq-artemis', 'apache_activemq',
    'apache_cordova-plugin-file-transfer',
    'apache_cordova-plugin-inappbrowser', 'apache_cxf-fediz', 'apache_cxf',
    'apache_incubator-livy', 'apache_incubator-openwhisk-runtime-docker',
    'apache_incubator-openwhisk-runtime-php', 'apache_ofbiz-framework',
    'apache_openoffice', 'apache_vcl', 'apexcharts_apexcharts.js',
    'apollosproject_apollos-apps', 'apostrophecms_apostrophe', 'apple_cups',
    'appneta_tcpreplay', 'aptana_jaxer', 'aquaverde_aquarius-core',
    'aquynh_capstone', 'arangodb_arangodb', 'archivy_archivy',
    'ardatan_graphql-tools', 'ardour_ardour', 'area17_twill', 'aresch_rencode',
    'argoproj_argo-cd', 'arjunmat_slack-chat', 'arrow-kt_arrow',
    'arsenal21_all-in-one-wordpress-security',
    'arsenal21_simple-download-monitor', 'arslancb_clipbucket',
    'artifexsoftware_ghostpdl', 'artifexsoftware_jbig2dec',
    'asaianudeep_deep-override', 'ashinn_irregex', 'askbot_askbot-devel',
    'assfugil_nickchanbot', 'asteinhauser_fat_free_crm', 'atheme_atheme',
    'atheme_charybdis', 'atinux_schema-inspector', 'att_ast',
    'auracms_auracms', 'aurelia_path', 'auth0_ad-ldap-connector',
    'auth0_auth0.js', 'auth0_express-jwt', 'auth0_express-openid-connect',
    'auth0_lock', 'auth0_nextjs-auth0', 'auth0_node-auth0',
    'auth0_node-jsonwebtoken', 'auth0_omniauth-auth0', 'authelia_authelia',
    'authguard_authguard', 'authzed_spicedb', 'automattic_genericons',
    'automattic_mongoose', 'autotrace_autotrace', 'autovance_ftp-srv',
    'avar_plack', 'avast_retdec', 'awslabs_aws-js-s3-explorer',
    'awslabs_tough', 'aws_aws-sdk-js-v3', 'aws_aws-sdk-js',
    'axdoomer_doom-vanille', 'axios_axios', 'axkibe_lsyncd', 'b-heilman_bmoor',
    'babelouest_glewlwyd', 'babelouest_ulfius', 'bacula-web_bacula-web',
    'badongdyc_fangfacms', 'bagder_curl', 'balderdashy_sails-hook-sockets',
    'ballerina-platform_ballerina-lang', 'bbangert_beaker',
    'bbengfort_confire', 'bblanchon_arduinojson', 'bblfsh_bblfshd',
    'bcfg2_bcfg2', 'bcit-ci_codeigniter', 'bcosca_fatfree-core',
    'bdew-minecraft_bdlib', 'beanshell_beanshell', 'behdad_harfbuzz',
    'belledonnecommunications_belle-sip', 'belledonnecommunications_bzrtp',
    'benjaminkott_bootstrap_package', 'bertramdev_asset-pipeline',
    'bettererrors_better_errors', 'billz_raspap-webgui', 'bit-team_backintime',
    'bitcoin_bitcoin', 'bitlbee_bitlbee', 'bitmessage_pybitmessage',
    'bittorrent_bootstrap-dht', 'blackcatdevelopment_blackcatcms',
    'blackducksoftware_hub-rest-api-python', 'blogifierdotnet_blogifier',
    'blogotext_blogotext', 'blosc_c-blosc2', 'bludit_bludit',
    'blueness_sthttpd', 'bluez_bluez', 'bminor_bash', 'bminor_glibc',
    'bonzini_qemu', 'boonebgorges_buddypress-docs', 'boonstra_slideshow',
    'boothj5_profanity', 'bottlepy_bottle', 'bouke_django-two-factor-auth',
    'bower_bower', 'boxug_trape', 'bradyvercher_gistpress',
    'braekling_wp-matomo', 'bratsche_pango', 'brave_brave-core', 'brave_muon',
    'briancappello_flask-unchained', 'brocaar_chirpstack-network-server',
    'broofa_node-uuid', 'brookinsconsulting_bccie', 'browserless_chrome',
    'browserslist_browserslist', 'browserup_browserup-proxy', 'bro_bro',
    'btcpayserver_btcpayserver', 'buddypress_buddypress',
    'bytecodealliance_lucet', 'bytom_bytom', 'c-ares_c-ares', 'c2fo_fast-csv',
    'cakephp_cakephp', 'canarymail_mailcore2', 'candlepin_candlepin',
    'candlepin_subscription-manager', 'canonicalltd_subiquity', 'caolan_forms',
    'capnproto_capnproto', 'carltongibson_django-filter',
    'carrierwaveuploader_carrierwave', 'catfan_medoo',
    'cauldrondevelopmentllc_cbang', 'ccxvii_mujs', 'cdcgov_microbetrace',
    'cdrummond_cantata', 'cdr_code-server', 'ceph_ceph-deploy',
    'ceph_ceph-iscsi-cli', 'certtools_intelmq-manager', 'cesanta_mongoose-os',
    'cesanta_mongoose', 'cesnet_perun', 'chalk_ansi-regex', 'charleskorn_kaml',
    'charybdis-ircd_charybdis', 'chaskiq_chaskiq', 'chatsecure_chatsecure-ios',
    'chatwoot_chatwoot', 'check-spelling_check-spelling', 'cherokee_webserver',
    'chevereto_chevereto-free', 'chillu_silverstripe-framework', 'chjj_marked',
    'chocolatey_boxstarter', 'chopmo_rack-ssl', 'chrisd1100_uncurl',
    'chyrp_chyrp', 'circl_ail-framework', 'cisco-talos_clamav-devel',
    'cisco_thor', 'civetweb_civetweb', 'ckeditor_ckeditor4',
    'ckolivas_cgminer', 'claviska_simple-php-captcha', 'clientio_joint',
    'cloudendpoints_esp', 'cloudfoundry_php-buildpack',
    'clusterlabs_pacemaker', 'cmuir_uncurl', 'cnlh_nps', 'cobbler_cobbler',
    'cockpit-project_cockpit', 'codecov_codecov-node',
    'codehaus-plexus_plexus-archiver', 'codehaus-plexus_plexus-utils',
    'codeigniter4_codeigniter4', 'codemirror_codemirror', 'codiad_codiad',
    'cog-creators_red-dashboard', 'cog-creators_red-discordbot',
    'collectd_collectd', 'commenthol_serialize-to-js',
    'common-workflow-language_cwlviewer', 'composer_composer',
    'composer_windows-setup', 'concrete5_concrete5-legacy',
    'containers_bubblewrap', 'containers_image', 'containers_libpod',
    'containous_traefik', 'contiki-ng_contiki-ng', 'convos-chat_convos',
    'cooltey_c.p.sub', 'coreutils_gnulib', 'corosync_corosync',
    'cosenary_instagram-php-api', 'cosmos_cosmos-sdk', 'cotonti_cotonti',
    'coturn_coturn', 'crater-invoice_crater', 'crawl_crawl',
    'creatiwity_witycms', 'creharmony_node-etsy-client',
    'crowbar_barclamp-crowbar', 'crowbar_barclamp-deployer',
    'crowbar_barclamp-trove', 'crowbar_crowbar-openstack',
    'crypto-org-chain_cronos', 'cthackers_adm-zip', 'ctripcorp_apollo',
    'ctz_rustls', 'cubecart_v6', 'cure53_dompurify', 'cvandeplas_pystemon',
    'cve-search_cve-search', 'cveproject_cvelist',
    'cyberark_conjur-oss-helm-chart', 'cyberhobo_wordpress-geo-mashup',
    'cydrobolt_polr', 'cyrusimap_cyrus-imapd', 'cyu_rack-cors',
    'd0c-s4vage_lookatme', 'd4software_querytree', 'daaku_nodejs-tmpl',
    'dagolden_capture-tiny', 'dajobe_raptor', 'daltoniam_starscream',
    'dandavison_delta', 'dankogai_p5-encode', 'danschultzer_pow',
    'darktable-org_rawspeed', 'darold_squidclamav', 'dart-lang_sdk',
    'darylldoyle_svg-sanitizer', 'dashbuilder_dashbuilder',
    'datacharmer_dbdeployer', 'datatables_datatablessrc',
    'datatables_dist-datatables', 'dav-git_dav-cogs', 'davegamble_cjson',
    'davidben_nspluginwrapper', 'davideicardi_confinit',
    'davidjclark_phpvms-popupnews', 'daylightstudio_fuel-cms',
    'dbeaver_dbeaver', 'dbijaya_onlinevotingsystem', 'dcit_perl-crypt-jwt',
    'debiki_talkyard', 'deislabs_oras', 'delta_pragyan',
    'delvedor_find-my-way', 'demon1a_discord-recon', 'denkgroot_spina',
    'deoxxa_dotty', 'dependabot_dependabot-core', 'derf_feh',
    'derickr_timelib', 'derrekr_android_security', 'desrt_systemd-shim',
    'deuxhuithuit_symphony-2', 'devsnd_cherrymusic', 'dexidp_dex',
    'dgl_cgiirc', 'dhis2_dhis2-core', 'diegohaz_bodymen', 'diegohaz_querymen',
    'dieterbe_uzbl', 'digint_btrbk', 'digitalbazaar_forge',
    'dingelish_rust-base64', 'dinhviethoa_libetpan', 'dino_dino',
    'directus_app', 'directus_directus', 'discourse_discourse-footnote',
    'discourse_discourse-reactions', 'discourse_message_bus',
    'discourse_rails_multisite', 'diversen_gallery', 'divio_django-cms',
    'diygod_rsshub', 'djabberd_djabberd', 'django-helpdesk_django-helpdesk',
    'django-wiki_django-wiki', 'dlitz_pycrypto', 'dmendel_bindata',
    'dmgerman_ninka', 'dmlc_ps-lite', 'dmproadmap_roadmap',
    'dnnsoftware_dnn.platform', 'docker_cli',
    'docker_docker-credential-helpers', 'docsifyjs_docsify', 'doctrine_dbal',
    'documize_community', 'dogtagpki_pki', 'dojo_dijit', 'dojo_dojo',
    'dojo_dojox', 'dollarshaveclub_shave', 'dom4j_dom4j', 'domoticz_domoticz',
    'dompdf_dompdf', 'doorgets_doorgets', 'doorkeeper-gem_doorkeeper',
    'dosfstools_dosfstools', 'dotcms_core', 'dotse_zonemaster-gui',
    'dottgonzo_node-promise-probe', 'dovecot_core', 'doxygen_doxygen',
    'dozermapper_dozer', 'dpgaspar_flask-appbuilder', 'dracutdevs_dracut',
    'dramforever_vscode-ghc-simple', 'drk1wi_portspoof', 'droolsjbpm_drools',
    'droolsjbpm_jbpm-designer', 'droolsjbpm_jbpm',
    'droolsjbpm_kie-wb-distributions', 'dropbox_lepton',
    'dropwizard_dropwizard', 'drudru_ansi_up', 'dspace_dspace',
    'dspinhirne_netaddr-rb', 'dsyman2_integriaims', 'dtschump_cimg',
    'duchenerc_artificial-intelligence', 'duffelhq_paginator',
    'dukereborn_cmum', 'duncaen_opendoas', 'dutchcoders_transfer.sh',
    'dvirtz_libdwarf', 'dweomer_containerd', 'dwisiswant0_apkleaks',
    'dw_mitogen', 'dynamoose_dynamoose', 'e107inc_e107',
    'e2guardian_e2guardian', 'e2openplugins_e2openplugin-openwebif',
    'eclipse-ee4j_mojarra', 'eclipse_mosquitto', 'eclipse_rdf4j',
    'eclipse_vert.x', 'edge-js_edge', 'edgexfoundry_app-functions-sdk-go',
    'edx_edx-platform', 'eflexsystems_node-samba-client', 'eggjs_extend2',
    'egroupware_egroupware', 'eiskalteschatten_compile-sass',
    'eivindfjeldstad_dot', 'elabftw_elabftw', 'elastic_elasticsearch',
    'eldy_awstats', 'elementary_switchboard-plug-bluetooth',
    'elementsproject_lightning', 'elixir-plug_plug', 'ellson_graphviz',
    'elmar_ldap-git-backup', 'elric1_knc', 'elves_elvish', 'embedthis_appweb',
    'embedthis_goahead', 'emca-it_energy-log-server-6.x', 'emlog_emlog',
    'enalean_gitphp', 'enferex_pdfresurrect', 'ensc_irssi-proxy',
    'ensdomains_ens', 'enviragallery_envira-gallery-lite', 'envoyproxy_envoy',
    'ericcornelissen_git-tag-annotation-action', 'ericcornelissen_shescape',
    'ericnorris_striptags', 'ericpaulbishop_gargoyle',
    'erikdubbelboer_phpredisadmin', 'erlang_otp', 'erlyaws_yaws',
    'esl_mongooseim', 'esnet_iperf', 'esphome_esphome', 'ethereum_go-ethereum',
    'ethereum_solidity', 'ether_ueberdb', 'ettercap_ettercap',
    'eugeneware_changeset', 'eugeny_ajenti', 'evangelion1204_multi-ini',
    'evanphx_json-patch', 'evilnet_nefarious2', 'evilpacket_marked',
    'excon_excon', 'exiftool_exiftool', 'exim_exim',
    'express-handlebars_express-handlebars', 'eyesofnetworkcommunity_eonweb',
    'ezsystems_ezjscore', 'f21_jwt', 'fabiocaccamo_utils.js', 'fabpot_twig',
    'facebookincubator_fizz', 'facebookincubator_mvfst',
    'facebookresearch_parlai', 'facebook_buck', 'facebook_folly',
    'facebook_mcrouter', 'facebook_nuclide', 'facebook_react-native',
    'facebook_wangle', 'facebook_zstd', 'faisalman_ua-parser-js',
    'faiyazalam_wordpress-plugin-user-login-history', 'fardog_trailing-slash',
    'fasterxml_jackson-dat'
]

OUTPUT_DIRNAME = 'graphql'

# copied from https://github.com/n0vad3v/get-profile-data-of-repo-stargazers-graphql

token = "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"
headers = {"Authorization": "token " + token}

generalQL = """
{{
  repository(name: "{0}", owner: "{1}") {{
    {2}(first: 100 {3}) {{	
          totalCount
          pageInfo {{
            endCursor
            hasPreviousPage
            startCursor
          }}
          edges {{
            cursor
            node {{
              createdAt
            }}
          }}
    }}
  }}
}}

"""

stargazer_query = """
{{
  repository(name: "{0}", owner: "{1}") {{
    stargazers(first: 100 {2}) {{	
        totalCount
        pageInfo {{
        endCursor
        hasPreviousPage
        startCursor
      }}
      edges {{
        starredAt
      }}
    }}
  }}
}}
"""

# todo check if we can find commits from other branches
commits_ql = """
{{
  repository(name: "{0}",owner: "{1}") {{
    object(expression: "{2}") {{
      ... on Commit {{
        history (first:100 {3}){{
          totalCount
          pageInfo{{
            endCursor
          }}
          nodes {{
            committedDate
            deletions
            additions
            oid
          }}
          pageInfo {{
            endCursor
          }}
        }}
      }}
    }}
  }}
}}
"""

branches_ql = """
{{
  repository(owner: "{0}", name: "{1}") {{
    refs(first: 50, refPrefix:"refs/heads/") {{
      nodes {{
        name
      }}
    }}
  }}
}}

"""

repo_meta_data = """
{{
  repository(owner: "{0}", name: "{1}") {{
    owner {{
      
      ... on User {{
        company
        isEmployee
        isHireable
        isSiteAdmin
        isGitHubStar
        isSponsoringViewer
        isCampusExpert
        isDeveloperProgramMember
      }}
      ... on Organization {{
        
        isVerified        
      }}
    }}
    isInOrganization
    createdAt
    diskUsage
    hasIssuesEnabled
    hasWikiEnabled
    isMirror
    isSecurityPolicyEnabled
    fundingLinks {{
      platform
    }}
    primaryLanguage {{
      name
    }}
    languages(first: 100) {{
      edges {{
        node {{
          name
        }}
      }}
    }}
  }}
}}

"""

attrib_list = [
    "vulnerabilityAlerts", "forks", "issues", "pullRequests", "releases",
    "stargazers"
]


def run_query(query):
    """sends a query to the github graphql api and returns the result as json"""
    counter = 0
    while True:
        request = requests.post('https://api.github.com/graphql',
                                json={'query': query},
                                headers=headers)
        if request.status_code == 200:
            return request.json()
        elif request.status_code == 502:
            raise RuntimeError(
                f"Query failed to run by returning code of {request.status_code}. {request}"
            )

        else:
            request_json = request.json()
            if "errors" in request_json and (
                    "timeout" in request_json["errors"][0]["message"]
                    or request_json["errors"]["type"] == 'RATE_LIMITED'):

                print("Waiting for an hour")
                print(request, request_json)
                counter += 1
                if counter < 6:
                    time.sleep(60 * 60)
                    continue
                break

            raise RuntimeError(
                f"Query failed to run by returning code of {request.status_code}. {query}"
            )


def flatten(d, parent_key='', sep='_'):
    """flatten a nested dict"""
    items = []
    for k, v in d.items():
        new_key = parent_key + sep + k if parent_key else k
        if isinstance(v, collections.MutableMapping):
            items.extend(flatten(v, new_key, sep=sep).items())
        else:
            items.append((new_key, v))
    return dict(items)


def get_commit_metadata(owner, repo):
    """get commit metadata from all branches"""
    res = run_query(repo_meta_data.format(owner, repo))
    if not res['data']['repository']:
        return None
    res = flatten(res['data']['repository'])
    res['languages_edges'] = list(
        map(lambda lang: lang['node']['name'], res['languages_edges']))

    return res


def get_all_commits(owner, repo):
    """
    Get all commits from all branches
    """
    branch_lst = run_query(branches_ql.format(owner, repo))
    branch_lst = [
        res['name']
        for res in branch_lst['data']['repository']['refs']['nodes']
    ]
    commit_date, additions, deletions, oids = [], [], [], []
    final_lst = []
    if "master" in branch_lst:
        final_lst.append('master')
    if "main" in branch_lst:
        final_lst.append('main')

    for branch in branch_lst:
        print(f"\t\t{branch}")
        cur_commit_date, cur_additions, cur_deletions, cur_oids = get_commits(
            owner, repo, branch)
        commit_date += cur_commit_date
        additions += cur_additions
        deletions += cur_deletions
        oids += cur_oids
    return commit_date, additions, deletions, oids


def get_commits(owner, repo, branch):
    """Get commits from a branch"""
    endCursor = ""  # Start from begining
    this_query = commits_ql.format(repo, owner, branch, endCursor)
    commit_date, additions, deletions, oid = [], [], [], []

    result = run_query(this_query)  # Execute the query
    if "data" in result and result["data"]["repository"]["object"] is not None:
        total_count = result['data']['repository']['object']['history'][
            'totalCount']
        for _ in range(0, total_count, 100):
            endCursor = result['data']['repository']['object']['history'][
                'pageInfo']['endCursor']
            for val in result['data']['repository']['object']['history'][
                    'nodes']:
                if val is not None:
                    commit_date.append(val['committedDate'])
                    additions.append(val['additions'])
                    deletions.append(val['deletions'])
                    oid.append(val['oid'])

            result = run_query(
                commits_ql.format(repo, owner, branch,
                                  'after:"{0}"'.format(endCursor)))
            if "data" not in result:
                print("Error3", result)
                break
    else:
        print("Error4", result)

    return additions, deletions, commit_date, oid


def get_stargazers(owner, repo):
    """
    Get all the stargazers of a repo
    """
    endCursor = ""  # Start from begining
    this_query = stargazer_query.format(repo, owner, endCursor)
    has_next_page = True
    staredAt = []
    result = run_query(this_query)  # Execute the query
    if "data" in result:
        total_count = result['data']['repository']['stargazers']['totalCount']
        for _ in range(0, total_count, 100):
            endCursor = result['data']['repository']['stargazers']['pageInfo'][
                'endCursor']
            staredAt.extend(
                val['starredAt']
                for val in result['data']['repository']['stargazers']['edges'])

            result = run_query(
                stargazer_query.format(repo, owner,
                                       'after:"{0}"'.format(endCursor)))
            if "data" not in result:
                raise RuntimeError(f"result {result} does not contain data")
    else:
        logging.error(result)
        raise RuntimeError(
            f"Query failed to run by returning code of {result}. {this_query}")
    return staredAt


def get_attribute(owner, repo, attribute):
    endCursor = ""  # Start from begining
    this_query = generalQL.format(repo, owner, attribute, endCursor)
    dates = []
    result = run_query(this_query)  # Execute the query
    if 'data' in result:
        total_count = result['data']['repository'][attribute]['totalCount']
        for _ in range(0, total_count, 100):
            endCursor = result['data']['repository'][attribute]['pageInfo'][
                'endCursor']
            dates.extend(
                val['node']['createdAt']
                for val in result['data']['repository'][attribute]['edges'])

            result = run_query(
                generalQL.format(repo, owner, attribute,
                                 'after:"{0}"'.format(endCursor)))
            if 'data' not in result:
                break

    else:
        logging.error("Attribute acquire error:", result)
    return dates


def get_repo(output_dir, repo):

    safe_mkdir(os.path.join(output_dir, OUTPUT_DIRNAME))

    owner = repo.split('/')[0]
    repo = repo.split('/')[1]

    logging.debug(f"Getting repo {repo} from {owner}")
    res_dict = {}
    for attribute in attrib_list:
        logging.debug("\t" + attribute)
        if attribute == "stargazers":
            res_dict[attribute] = get_stargazers(owner, repo)
        elif attribute == "commits":
            res_dict['additions'], res_dict['deletions'], res_dict[
                'commit_date'], res_dict['oid'] = get_all_commits(owner, repo)
        else:
            res_dict[attribute] = get_attribute(owner, repo, attribute)

    with open(os.path.join(output_dir, OUTPUT_DIRNAME, f"{owner}_{repo}.csv"),
              "w",
              newline='') as outfile:
        writer = csv.writer(outfile)
        writer.writerow(res_dict.keys())
        writer.writerows(itertools.zip_longest(*res_dict.values()))


def get_date_for_commit(repo, commit):
    owner = repo.split('/')[0]
    repo = repo.split('/')[1]
    ql_query = """
    {{
      repository(owner: "{0}", name: "{1}") {{
        object(expression: "{2}") {{
          ... on Commit {{
            committedDate
          }}
        }}
      }}
    }}""".format(owner, repo, commit)
    result = run_query(ql_query)
    if "errors" in result:
        print("ERROR1", ql_query, result)
        raise RepoNotFoundError()
    if "data" in result and result["data"]["repository"]["object"] is not None:
        return result["data"]["repository"]["object"]["committedDate"]
    print("ERROR2", ql_query, result)
    raise RepoNotFoundError()


def get_date_for_alternate_proj_commit(proj_name, commit_hash):
    owner = proj_name.split('/')[0]
    repo = proj_name.split('/')[1]
    query = """{{
          search(query: "{0}", type: REPOSITORY, first: 100) {{
            repositoryCount
            edges {{
              node {{
                ... on Repository {{
                  nameWithOwner
                  name
                }}
              }}
            }}
          }}
        }}
    
    """

    result = run_query(query.format(repo))
    if "data" not in result:
        return None, None
    for res in result['data']['search']['edges']:
        cur_repo = res['node']['nameWithOwner']
        if res['node']['name'] != repo:
            continue
        url = "http://www.github.com/{0}/commit/{1}".format(
            cur_repo, commit_hash)
        f = requests.get(url)
        print(url, f.status_code)
        if f.status_code == 200:
            try:
                return cur_repo, get_date_for_commit(cur_repo, commit_hash)
            except RepoNotFoundError:
                pass

    return None, None


all_langs = [
    '1C Enterprise', 'AGS Script', 'AIDL', 'AMPL', 'ANTLR', 'API Blueprint',
    'ASL', 'ASP', 'ASP.NET', 'ActionScript', 'Ada', 'Agda', 'Alloy',
    'AngelScript', 'ApacheConf', 'Apex', 'AppleScript', 'Arc', 'AspectJ',
    'Assembly', 'Asymptote', 'Augeas', 'AutoHotkey', 'AutoIt', 'Awk', 'BASIC',
    'Ballerina', 'Batchfile', 'Berry', 'Bicep', 'Bikeshed', 'BitBake', 'Blade',
    'BlitzBasic', 'Boogie', 'Brainfuck', 'Brightscript', 'C', 'C#', 'C++',
    'CMake', 'COBOL', 'CSS', 'CUE', 'CWeb', 'Cadence', "Cap'n Proto", 'Ceylon',
    'Chapel', 'Charity', 'ChucK', 'Clarion', 'Classic ASP', 'Clean', 'Clojure',
    'Closure Templates', 'CodeQL', 'CoffeeScript', 'ColdFusion', 'Common Lisp',
    'Common Workflow Language', 'Coq', 'Cuda', 'Cython', 'D',
    'DIGITAL Command Language', 'DM', 'DTrace', 'Dart', 'Dhall', 'Dockerfile',
    'Dylan', 'E', 'ECL', 'EJS', 'Eiffel', 'Elixir', 'Elm', 'Emacs Lisp',
    'EmberScript', 'Erlang', 'Euphoria', 'F#', 'F*', 'FLUX', 'Fancy', 'Faust',
    'Filebench WML', 'Fluent', 'Forth', 'Fortran', 'FreeBasic', 'FreeMarker',
    'GAP', 'GCC Machine Description', 'GDB', 'GDScript', 'GLSL', 'GSC',
    'Game Maker Language', 'Genshi', 'Gherkin', 'Gnuplot', 'Go', 'Golo',
    'Gosu', 'Groff', 'Groovy', 'HCL', 'HLSL', 'HTML', 'Hack', 'Haml',
    'Handlebars', 'Haskell', 'Haxe', 'Hy', 'IDL', 'IGOR Pro', 'Inform 7',
    'Inno Setup', 'Ioke', 'Isabelle', 'Jasmin', 'Java', 'JavaScript',
    'JetBrains MPS', 'Jinja', 'Jolie', 'Jsonnet', 'Julia', 'Jupyter Notebook',
    'KRL', 'Kotlin', 'LLVM', 'LSL', 'Lasso', 'Latte', 'Less', 'Lex', 'Limbo',
    'Liquid', 'LiveScript', 'Logos', 'Lua', 'M', 'M4', 'MATLAB', 'MAXScript',
    'MLIR', 'MQL4', 'MQL5', 'Macaulay2', 'Makefile', 'Mako', 'Mathematica',
    'Max', 'Mercury', 'Meson', 'Metal', 'Modelica', 'Modula-2', 'Modula-3',
    'Module Management System', 'Monkey', 'Moocode', 'MoonScript', 'Motoko',
    'Mustache', 'NASL', 'NSIS', 'NewLisp', 'Nextflow', 'Nginx', 'Nim', 'Nit',
    'Nix', 'Nu', 'OCaml', 'Objective-C', 'Objective-C++', 'Objective-J',
    'Open Policy Agent', 'OpenEdge ABL', 'PEG.js', 'PHP', 'PLSQL', 'PLpgSQL',
    'POV-Ray SDL', 'Pan', 'Papyrus', 'Pascal', 'Pawn', 'Perl', 'Perl 6',
    'Pike', 'Pony', 'PostScript', 'PowerShell', 'Processing', 'Procfile',
    'Prolog', 'Promela', 'Pug', 'Puppet', 'PureBasic', 'PureScript', 'Python',
    'QML', 'QMake', 'R', 'RAML', 'REXX', 'RPC', 'RPGLE', 'RUNOFF', 'Racket',
    'Ragel', 'Ragel in Ruby Host', 'Raku', 'ReScript', 'Reason', 'Rebol',
    'Red', 'Redcode', 'RenderScript', 'Rich Text Format', 'Riot',
    'RobotFramework', 'Roff', 'RouterOS Script', 'Ruby', 'Rust', 'SAS', 'SCSS',
    'SMT', 'SQLPL', 'SRecode Template', 'SWIG', 'Sage', 'SaltStack', 'Sass',
    'Scala', 'Scheme', 'Scilab', 'Shell', 'ShellSession', 'Sieve', 'Slice',
    'Slim', 'SmPL', 'Smali', 'Smalltalk', 'Smarty', 'Solidity', 'SourcePawn',
    'Stan', 'Standard ML', 'Starlark', 'Stata', 'StringTemplate', 'Stylus',
    'SuperCollider', 'Svelte', 'Swift', 'SystemVerilog', 'TLA', 'TSQL', 'Tcl',
    'TeX', 'Tea', 'Terra', 'Thrift', 'Turing', 'Twig', 'TypeScript',
    'UnrealScript', 'VBA', 'VBScript', 'VCL', 'VHDL', 'Vala',
    'Velocity Template Language', 'Verilog', 'Vim Snippet', 'Vim script',
    'Visual Basic', 'Visual Basic .NET', 'Volt', 'Vue', 'WebAssembly', 'Wren',
    'X10', 'XProc', 'XQuery', 'XS', 'XSLT', 'Xtend', 'YARA', 'Yacc', 'Yul',
    'Zeek', 'Zig', 'eC', 'jq', 'kvlang', 'mupad', 'nesC', 'q', 'sed', 'xBase'
]
#Graphql end


logging.basicConfig(
    filename='last_run.log',
    filemode='w',
    format='%(asctime)s,%(msecs)d %(name)s %(levelname)s %(message)s',
    datefmt='%H:%M:%S',
    level=logging.DEBUG)

logger = logging.getLogger('analyze_cve')
logger.setLevel(logging.DEBUG)

logger.addHandler(logging.StreamHandler())

GITHUB_ARCHIVE_DIRNAME = "gharchive"
gh_cve_dir = "gh_cve_proccessed"
commit_directory = "commits"
json_commit_directory = "json_commits"
timezone_directory = "timezones"
repo_metadata_filename = "repo_metadata.json"

LOG_GRAPHQL = "graphql_errlist.txt"
LOG_AGGR_ALL = 'gharchive_errlist.txt'
key_list = set()
err_counter = 0
ref_keys = [
    'ASCEND', 'ENGARDE', 'VIM', 'ERS', 'ATSTAKE', 'JVNDB', 'SLACKWARE',
    'ENGARDE', 'OPENBSD', 'CIAC', 'IBM', 'SUNALERT', 'FARMERVENEMA', 'XF',
    'ALLAIRE', 'VULN-DEV', 'MSKB', 'VULNWATCH', 'AIXAPAR', 'CERT-VN',
    'NTBUGTRAQ', 'XF', 'SUSE', 'CONECTIVA', 'SEKURE', 'MISC', 'MSKB', 'SUNBUG',
    'TURBO', 'VUPEN', 'BUGTRAQ', 'BUGTRAQ', 'DEBIAN', 'SCO', 'MS', 'IDEFENSE',
    'MLIST', 'INFOWAR', 'SECUNIA', 'FULLDISC', 'SUN', 'KSRT', 'HP', 'BID',
    'EL8', 'MANDRAKE', 'IMMUNIX', 'SECTRACK', 'VULN-DEV', 'CONFIRM', 'GENTOO',
    'SECTRACK', 'EL8', 'VUPEN', 'CERT', 'FREEBSD', 'HERT', 'L0PHT', 'BID',
    'CONECTIVA', 'SREASONRES', 'SCO', 'FEDORA', 'NAI', 'AUSCERT', 'ISS',
    'COMPAQ', 'NETECT', 'SUNBUG', 'CHECKPOINT', ' 1.23.1)', 'WIN2KSEC', 'BEA',
    'EXPLOIT-DB', 'KSRT', 'MANDRAKE', 'FRSIRT', 'JVN', 'RSI', 'NETBSD',
    'AUSCERT', 'OPENPKG', 'OPENBSD', 'CERT-VN', 'SUN', 'SECUNIA', 'VIM',
    'GENTOO', 'REDHAT', 'MS', 'COMPAQ', 'OVAL', 'CALDERA', 'FEDORA', 'FREEBSD',
    'CISCO', 'CISCO', 'WIN2KSEC', 'MANDRIVA', 'OSVDB', 'UBUNTU', 'EEYE', 'BEA',
    'IDEFENSE', 'NETBSD', 'SGI', 'SREASON', 'OSVDB', 'CIAC', 'BINDVIEW',
    'FULLDISC', 'NTBUGTRAQ', 'URL', 'MISC', 'MANDRIVA', 'OVAL', 'MLIST',
    'L0PHT', 'UBUNTU', 'AIXAPAR', 'REDHAT', 'EXPLOIT-DB', 'IBM', 'SGI',
    'APPLE', 'SF-INCIDENTS', 'APPLE', 'ERS', 'RSI', 'BINDVIEW', 'TRUSTIX',
    'CALDERA', 'ISS', 'DEBIAN', 'FARMERVENEMA', 'HPBUG', 'ATSTAKE', 'SREASON',
    'JVN', 'CERT', 'NAI', 'SUNALERT', 'TURBO', 'VULNWATCH', 'CONFIRM', 'HP',
    'SNI', 'SUSE'
]
EXTENSION_NUM = 300
github_list = ['MLIST', 'CONFIRM', 'MISC', 'URL', 'CONFIRM', 'XF', 'MISC']
DATE_COLUMNS = ["vulnerabilityAlerts","forks","issues","pullRequests","releases","stargazers"]
github_counter = 0




def ref_parser(ref_row):
    """

    :param ref_row: a reference to be parsed
    :return: a list of urls that might point to a commit
    """
    global github_counter
    refs = ref_row.split('|')
    ret_dict = {}
    has_github_ref = 0
    for ref in refs:
        with contextlib.suppress(ValueError):
            key, val = ref.split(":", 1)
            key = key.replace(' ', '')
            if "github" in val.lower():
                has_github_ref = 1
            if key in ret_dict:
                ret_dict[key].append(val)
            else:
                ret_dict[key] = [val]
    for ref_key in ref_keys:
        if ref_key not in ret_dict:
            ret_dict[ref_key] = []
    github_counter += has_github_ref
    return [ret_dict[x] for x in github_list] + [has_github_ref]


def handle_duplicate_key(key, ret_dict, val):
    found = False
    for i in range(1, EXTENSION_NUM):
        if f'{key}{i}' not in ret_dict:
            ret_dict[f'{key}{i}'] = val
            found = True
            break
    if not found:
        raise RuntimeError(f'{key} already in dict')


# token = open(r'C:\secrets\github_token.txt', 'r').read()
# g = Github(token)


def gather_pages(obj):
    obj_list = []
    obj.__requester.per_page = 100
    for i in range(0, obj.totalCount, 30):
        retry = True
        counter = 0
        while retry and counter < 100:
            try:
                retry = False
                for obj_instance in obj.get_page(i // 30):
                    obj_instance._completeIfNeeded = lambda: None
                    obj_list.append(obj_instance.raw_data)
            except Exception as e:
                print(obj)
                traceback.print_exc()
                counter += 1
    return obj_list


# todo For commits, get also additions and deletions
# todo number of subscriptions is not supported
# todo watchers and subscribers ??
attributes = [
    'commits', 'forks', 'comments', 'releases', 'events', 'issues', 'events',
    'pulls', 'pulls_comments', 'stargazers_with_dates'
]
attributes = ['stargazers_with_dates']
attributes = ['events']


def save_all_data(g, repo_name):
    repo = g.get_repo(repo_name)
    for attribute in attributes:
        print(f"\t{attribute}")
        Path(f"rawdata/{repo.name}").mkdir(parents=True, exist_ok=True)
        attr_func = repo.__getattribute__(f"get_{attribute}")
        with open(f'rawdata/{repo.name}/{attribute}.json', 'w') as fout:
            json.dump(gather_pages(attr_func()), fout, indent=4)


def yearly_preprocess(output_dir, repo_list):
    repo_dfs = []
    err_list = open("gh_yearly_errlist.txt", 'w')
    for repo_name, df in repo_list:
        if df[(df.type == 'VulnEvent')].empty:
            err_list.write(f"{repo_name}\n")
            continue
        day_df = pd.DataFrame()
        for col in df.type.unique():
            cur_type = df[(df.type == col)]
            if cur_type.empty:
                continue
            cur_df = pd.to_datetime(cur_type.created_at)
            cur_df = pd.DataFrame(cur_df).set_index('created_at')
            cur_df[col] = 1
            cur_df = cur_df.resample("D").sum()
            day_df = day_df.join(cur_df, how='outer')
            day_df = day_df.fillna(0)
        day_df.to_csv(f"{output_dir}/{repo_name.replace('/', '_')}.csv")


def parse_url(var):
    url = urlparse(var.lower())
    path = url.path + '/'
    commit_hash = ""
    if url.hostname != "github.com":
        return (None, None, None, None)
    if '/pull/' in path:
        if path.count('/') == 6:
            _, group, proj, pull, pull_num, commit, _ = path.split('/',
                                                                   maxsplit=6)
        else:
            _, group, proj, pull, pull_num, commit, commit_hash, _ = path.split(
                '/', maxsplit=7)
    else:
        _, group, proj, commit, commit_hash, _ = path.split('/', maxsplit=5)

    return group, proj, commit.replace(' ', ''), commit_hash


def extract_commits_from_projects_gh(cves):
    repo_commits = {}
    for _, row in cves[cves['has_github'] == 1].iterrows():
        for github_var in github_list:
            for var in row[github_var]:
                if '/commit' in var.lower():

                    group, proj, commit, commit_hash = parse_url(var)
                    if commit is None:
                        logger.debug(f"Unable to parse {var}")
                        continue

                    if commit in ['compare', 'blob']:
                        logger.debug(f"Unable to parse {var}")
                        continue

                    if commit not in ["commit", 'commits']:
                        logger.debug(f"Unable to parse {var}")
                        continue

                    proj_name = f"{group}/{proj}"
                    if proj_name not in repo_commits:
                        repo_commits[proj_name] = []

                    commit_hash = commit_hash.replace(' ', '')
                    commit_hash = commit_hash.replace('.patch', '')
                    commit_hash = commit_hash.replace('confirm:', '')
                    commit_hash = commit_hash[:40]
                    if commit_hash not in repo_commits[proj_name]:
                        repo_commits[proj_name].append(commit_hash)

    return repo_commits


def preprocess_dataframe(cves):
    cves = cves[~cves.ref.isna()]
    cves = cves.astype(str)
    new_ref_vals = zip(*cves['ref'].apply(ref_parser))
    for ref_val, name in zip(new_ref_vals, github_list + ['has_github']):
        cves[name] = ref_val
    return cves


datasets_foldername = "datasets"

output_dir = 'data_collection/data/datasets'

def cve_preprocess(output_dir, cache_csv=False):
    logger.debug("Downloading CVE dataset")
    datasets_foldername = "datasets"

    output_dir = 'data_collection/data/datasets'
    safe_mkdir(os.path.join(output_dir, datasets_foldername))
    if not cache_csv:
        cve_xml = "https://cve.mitre.org/data/downloads/allitems.csv"
        wget.download(cve_xml,
                      out=os.path.join(output_dir, datasets_foldername))

    cves = pd.read_csv(
        os.path.join(output_dir, datasets_foldername, "allitems.csv"),
        skiprows=11,
        encoding="ISO-8859-1",
        names=['cve', 'entry', 'desc', 'ref', 'assigned', 'un1', 'un2'],
        dtype=str)
    cves = preprocess_dataframe(cves)

    repo_commits = extract_commits_from_projects_gh(cves)
    with open(os.path.join(output_dir, 'repo_commits.json'), 'w') as fout:
        json.dump(repo_commits, fout, sort_keys=True, indent=4)


def graphql_preprocess(output_dir, project_name=None):
    with open(os.path.join(output_dir, 'repo_commits.json'), 'r') as fin:
        repo_commits = json.load(fin)

    repos = repo_commits.keys()
    for idx, repo in enumerate(repos):
        logger.debug(f"Processing {repo} ({idx}/{len(repos)})")

        if project_name is not None and not repo.endswith("/" + project_name):
            logger.error(f"Skipping {repo} since it has less that 10 CVEs")
            continue

        try:
            graphql.get_repo(output_dir, repo)
        except Exception as e:
            logger.error(f"Repository {repo} error at:" + repo +
                         traceback.format_exc())


def find_name(repo_commits, repo_name: str) -> str:
    return next(
        (key for key in repo_commits.keys() if key.endswith(f"/{repo_name}")),
        "")


def most_common(lst):
    return max(set(lst), key=lst.count) if lst else 0


def aggregate_all(output_dir):
    new_dfs = []

    with open(os.path.join(output_dir, 'repo_commits.json'), 'r') as fin:
        repo_commits = json.load(fin)

    # Getting graphql data

    print("[LOG] Getting graphql data:")
    for filename in os.listdir(os.path.join(output_dir,
                                            graphql.OUTPUT_DIRNAME))[:]:
        logger.debug(f"Getting graphql of {filename}")
        print(filename)
        df = pd.read_csv(
            os.path.join(output_dir, graphql.OUTPUT_DIRNAME, f"{filename}"))
        name = filename.split(".csv")[0]
        if df.empty:
            continue

        for col in DATE_COLUMNS:
            if not df[col].isnull().all():
                cur_df = pd.DataFrame()
                cur_df['created_at'] = pd.to_datetime(df[col].dropna())
                cur_df["type"] = col
                cur_df["name"] = name
                new_dfs.append(cur_df)

    # Getting gharchive data
    logger.debug("Getting gharchive data:")
    dfs = []
    for year in range(2015, 2020):
        logger.debug(f"gharchive of year {year}")
        dfs.append(
            pd.read_csv(
                os.path.join(output_dir, GITHUB_ARCHIVE_DIRNAME,
                             f'{year}.csv')))
    # adding vulnerabilities events

    logger.debug("Adding vulnerabilities events:")
    # Getting commit data

    repo_commit_df_lst = []
    for repo, vuln_commits in list(repo_commits.items())[:]:
        logger.debug(f"Aggregating repo {repo}")
        repo_real_name = repo.replace('/', '_')
        with open(
                os.path.join(output_dir, json_commit_directory,
                             f"{repo_real_name}.json"), 'r') as fin:
            all_commits = json.load(fin)

        for commit in all_commits:
            if commit[0] in vuln_commits:
                commit.append(1)
            else:
                commit.append(0)
            commit.append(repo_real_name)
            commit.append("Commit")

        repo_commit_df = pd.DataFrame(all_commits,
                                      columns=[
                                          'Hash', 'created_at', "Add", "Del",
                                          "Files", "Vuln", "name", "type"
                                      ])

        repo_commit_df_lst.append(
            repo_commit_df)  # df['Time'] = pd.to_datetime(df['Time'])

    logger.debug("Concatenating dataframes")
    df = pd.concat(dfs + repo_commit_df_lst + new_dfs)

    logger.debug("Replacing / with _")
    df.name = df.name.str.replace("/", "_")

    logger.debug("Grouping Dataframes")
    repo_list = list(df.groupby('name'))

    logger.debug("saving data to parquets")
    safe_mkdir(os.path.join(output_dir, gh_cve_dir))
    for repo_name, df in repo_list:
        logger.debug(f"Saving {repo_name} to parquet")
        df.to_csv(
            os.path.join(output_dir, gh_cve_dir,
                         f"{repo_name.replace('/', '_')}.csv"))


def extract_commits_from_projects(output_dir):

    safe_mkdir(os.path.join(output_dir, commit_directory))
    safe_mkdir(os.path.join(output_dir, json_commit_directory))

    with open(os.path.join(output_dir, 'repo_commits.json'), 'r') as fin:
        repo_commits = json.load(fin)

    for repo_name in repo_commits.keys():
        logger.debug(f"Processing {repo_name}")
        author, repo = repo_name.split("/")
        repo_directory = f"{author}_{repo}"
        commit_cur_dir = os.path.join(output_dir, commit_directory,
                                      repo_directory)
        repo_url = f"https://github.com/{repo_name}.git"

        subprocess.run(f"git clone --mirror {repo_url} {commit_cur_dir}",
                       shell=True)

        subprocess.run(f"git -C {commit_cur_dir} fetch --unshallow",
                       shell=True)
        commit_abs_path = os.path.abspath(commit_cur_dir)
        gitlog = run_git_log(commit_abs_path)
        jsons = git2jsons(gitlog)

        commits = json.loads(jsons)
        res = []
        timezones = []
        for commit in commits:
            # gathering timezones from commits
            tz = commit['committer']['timezone']
            tz = int(tz[:-2]) + int(tz[-2:]) / 60.0
            timezones.append(tz)

            adds, dels = 0, 0
            for change in commit['changes']:
                if change is not None:
                    if type(change[0]) == int:
                        adds += change[0]
                    if type(change[1]) == int:
                        dels += change[1]

            time = datetime.utcfromtimestamp(
                commit['committer']['date']).strftime('%Y-%m-%d %H:%M:%S')

            res.append(
                (commit['commit'], time, adds, dels, len(commit['changes'])))

        avg_timezone = most_common(timezones)
        with open(
                os.path.join(output_dir, json_commit_directory,
                             f'{author}_{repo}.json'), 'w') as fout:
            json.dump(res, fout, indent=4)
        safe_mkdir(os.path.join(output_dir, timezone_directory))
        with open(
                os.path.join(output_dir, timezone_directory,
                             f'{author}_{repo}.json'), 'w') as fout:
            fout.write(str(avg_timezone))


def metadata_preprocess(output_dir):
    all_langs = set()
    repos = {}

    with open(os.path.join(output_dir, 'repo_commits.json'), 'r') as fin:
        repo_commits = json.load(fin)

    for repo_name in repo_commits.keys():
        logger.debug(f"Processing {repo_name}")
        author, repo = repo_name.split("/")
        repo_metadata = graphql.get_commit_metadata(author, repo)
        if not repo_metadata:
            continue
        all_langs = all_langs.union(set(repo_metadata['languages_edges']))
        repos[repo_name] = repo_metadata

        # res['languages_edges']='|'.join(list(map(lambda lang: lang['node']['name'],res['languages_edges'])))

    with open(os.path.join(output_dir, repo_metadata_filename), 'w') as mfile:
        json.dump(repos, mfile)


def main(graphql=False,
         cve=False,
         metadata=False,
         commits=False,
         aggregate=False,
         all=False,
         output_dir="output"):
    if all or cve:
        cve_preprocess(output_dir)
    if all or graphql:
        graphql_preprocess(output_dir)
    if all or metadata:
        metadata_preprocess(output_dir)
    if all or commits:
        extract_commits_from_projects(output_dir)
    if all or aggregate:
        aggregate_all(output_dir)


if __name__ == '__main__':

    parser = argparse.ArgumentParser(description='Detects hidden cves')
    parser.add_argument("--cve",
                        action="store_true",
                        help="Runs cve preprocessing")
    parser.add_argument("--graphql",
                        action="store_true",
                        help="Runs graphql preprocessing")
    parser.add_argument("--metadata",
                        action="store_true",
                        help="Stores metadata of repository")
    parser.add_argument("--commits",
                        action="store_true",
                        help="acquire all commits")
    parser.add_argument(
        "--aggregate",
        action="store_true",
        help="Runs aggregation with graphql and gharpchive data")
    parser.add_argument("--all",
                        action="store_true",
                        help="Run all preprocessing steps")
    parser.add_argument("-o", "--output-dir", action="store", default="data")
    args = parser.parse_args()

    main(graphql=args.graphql,
         cve=args.cve,
         metadata=args.metadata,
         commits=args.commits,
         aggregate=args.aggregate,
         all=args.all,
         output_dir=args.output_dir)
