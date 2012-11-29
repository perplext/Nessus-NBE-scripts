<?php
// Since we're already using PHP5, why don't we exploit their easy to 
use file_get_contents() command?
$filename = "/path/to/input.nessus";
if (filesize($filename) > 0) {
$xmlFileData = file_get_contents("/path/to/input.nessus");
//Here's our Simple XML parser!
$xmlData = new SimpleXMLElement($xmlFileData);
//And here's the output.

// print_r($xmlData);

// Show Report Settings
echo 
",-----------------------------------------------------------------------------------------,\r\n";
echo "| Nessus Server Settings                                                                  
|\r\n";
echo 
"'-----------------------------------------------------------------------------------------'\r\n\r\n";
foreach($xmlData->Policy->Preferences->ServerPreferences->preference as 
$preference) {
        echo $preference->name . " = " . $preference->value . "\r\n";
}

// Show Plugin Preferences
echo "\r\n";
echo 
",-----------------------------------------------------------------------------------------,\r\n";
echo "| Nessus Server Plugin Preferences                                                        
|\r\n";
echo 
"'-----------------------------------------------------------------------------------------'\r\n\r\n";
foreach($xmlData->Policy->Preferences->PluginsPreferences->item as 
$item) {
        echo "Plug-in ID: " . $item->pluginId . "\r\n";
        echo "Plug-In Name: " . $item->pluginName . "\r\n";
        echo "Full Plug-In Name: " . $item->fullName . "\r\n";
        echo "Preference Name: " . $item->preferenceName . "\r\n";
        echo "Selected Value: " . $item->selectedValue . "\r\n";
        echo 
"-------------------------------------------------------------------------------------------\r\n";
}


// Show Hosts Summary
echo "\r\n";
echo 
",-----------------------------------------------------------------------------------------,\r\n";
echo "| Nessus Scan - Hosts Summary                                                             
|\r\n";
echo 
"'-----------------------------------------------------------------------------------------'\r\n\r\n";

  foreach($xmlData->Report->ReportHost as $host) {
        $ports = array();
//    print_r($host);
//      print_r($host->HostProperties);
//      echo $host->HostProperties->tag[1];

        /* get unique ips */
        $dnsnext = 0;
        foreach ($host->HostProperties->tag as $thetag) {
                if 
(preg_match('/^(([1-9]?[0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]).){3}([1-9]?[0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$/',$thetag)) 
{
                        $theip = $thetag;
                        $dnsnext = 1;
                } else {

                        if ($dnsnext == 1) { $thedns = $thetag; $dnsnext 
= 0; }
                }
        }
        echo $theip . " - " . $thedns . "\r\nOpen Ports: ";

        foreach ($host->ReportItem as $item) {
                array_push($ports, $item->attributes()->port);
        }
        sort($ports);
        $ports = array_unique($ports);
        $thecount = count($ports);
        $i = 0;
        foreach ($ports as $port) {
                $i++;
                echo $port;
                if ($i < $thecount) {
                        echo ",";
                }
        }

//    echo $host->HostProperties->tag->[1];
        echo "\r\n\r\n";
  }

// Show Vulnerabilities by Host
$critvulnerabilities = array();
$medvulnerabilities = array();
$lowvulnerabilities = array();
$infovulnerabilities = array();
echo "\r\n";
echo 
",-----------------------------------------------------------------------------------------,\r\n";
echo "| Nessus Scan - Vulnerabilities by Host                                                   
|\r\n";
echo 
"'-----------------------------------------------------------------------------------------'\r\n\r\n";

  foreach($xmlData->Report->ReportHost as $host) {
                foreach ($host->HostProperties->tag as $thetag) {
                if 
(preg_match('/^(([1-9]?[0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]).){3}([1-9]?[0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$/',$thetag)) 
{
                        $theip = $thetag;
                        $dnsnext = 1;
                } else {

                        if ($dnsnext == 1) { $thedns = $thetag; $dnsnext 
= 0; }
                }
                }
                echo $theip . " - " . $thedns . "\r\n";
                echo 
"---------------------------------------------------------------\r\n";
                foreach ($host->ReportItem as $item) {
                        if ($item->attributes()->severity == '3')
                                $tmpvuln = array("ip" => $theip, "dns" 
=> $thedns, "port" => $item->attributes()->port, "svc_name" => 
$item->attributes()->svc_name, "protocol" => 
$item->attributes()->protocol, "pluginID" => 
$item->attributes()->pluginID, "pluginName" => 
$item->attributes()->pluginName, "pluginFamily" => 
$item->attributes()->pluginFamily, "vuln_publication_date" => 
$item->vuln_publication_date, "cpe" => $item->cpe, "solution" => 
$item->solution, "risk_factor" => $item->risk_factor, "description" => 
$item->description, "plugin_publication_date" => 
$item->plugin_publication_date, "cvss_vector" => $item->cvss_vector, 
"synopsis" => $item->synopsis, "plugin_type" => $item->plugin_type, 
"patch_publication_date" => $item->patch_publication_date, 
"plugin_modification_date" => $item->plugin_modification_date, 
"cvss_base_score" => $item->cvss_base_score, "cve" => $item->cve, "bid" 
=> $item->bid, "xref" => $item->xref, "plugin_output" => 
$item->plugin_output, "plugin_version" => $item->plugin_version);
                                $critvulnerabilities[] = $tmpvuln;
                        }
                        if ( $item->attributes()->severity == '2') {
                                $tmpvuln = array("ip" => $theip, "dns" 
=> $thedns, "port" => $item->attributes()->port, "svc_name" => 
$item->attributes()->svc_name, "protocol" => 
$item->attributes()->protocol, "pluginID" => 
$item->attributes()->pluginID, "pluginName" => 
$item->attributes()->pluginName, "pluginFamily" => 
$item->attributes()->pluginFamily, "vuln_publication_date" => 
$item->vuln_publication_date, "cpe" => $item->cpe, "solution" => 
$item->solution, "risk_factor" => $item->risk_factor, "description" => 
$item->description, "plugin_publication_date" => 
$item->plugin_publication_date, "cvss_vector" => $item->cvss_vector, 
"synopsis" => $item->synopsis, "plugin_type" => $item->plugin_type, 
"patch_publication_date" => $item->patch_publication_date, 
"plugin_modification_date" => $item->plugin_modification_date, 
"cvss_base_score" => $item->cvss_base_score, "cve" => $item->cve, "bid" 
=> $item->bid, "xref" => $item->xref, "plugin_output" => 
$item->plugin_output, "plugin_version" => $item->plugin_version);
                                $medvulnerabilities[] = $tmpvuln;
                        }
                        if ( $item->attributes()->severity == '1') {
                                $tmpvuln = array("ip" => $theip, "dns" 
=> $thedns, "port" => $item->attributes()->port, "svc_name" => 
$item->attributes()->svc_name, "protocol" => 
$item->attributes()->protocol, "pluginID" => 
$item->attributes()->pluginID, "pluginName" => 
$item->attributes()->pluginName, "pluginFamily" => 
$item->attributes()->pluginFamily, "vuln_publication_date" => 
$item->vuln_publication_date, "cpe" => $item->cpe, "solution" => 
$item->solution, "risk_factor" => $item->risk_factor, "description" => 
$item->description, "plugin_publication_date" => 
$item->plugin_publication_date, "cvss_vector" => $item->cvss_vector, 
"synopsis" => $item->synopsis, "plugin_type" => $item->plugin_type, 
"patch_publication_date" => $item->patch_publication_date, 
"plugin_modification_date" => $item->plugin_modification_date, 
"cvss_base_score" => $item->cvss_base_score, "cve" => $item->cve, "bid" 
=> $item->bid, "xref" => $item->xref, "plugin_output" => 
$item->plugin_output, "plugin_version" => $item->plugin_version);
                                $lowvulnerabilities[] = $tmpvuln;
                        }
                        if ($item->attributes()->severity == '0') {
                                $tmpvuln = array("ip" => $theip, "dns" 
=> $thedns, "port" => $item->attributes()->port, "svc_name" => 
$item->attributes()->svc_name, "protocol" => 
$item->attributes()->protocol, "pluginID" => 
$item->attributes()->pluginID, "pluginName" => 
$item->attributes()->pluginName, "pluginFamily" => 
$item->attributes()->pluginFamily);
                                $infovulnerabilities = $tmpvuln;
                        }
                }
  }


/* Now that we have the information we need in 4 different arrays based 
on criticality, let's add everything to the database



Database architecture:

asset
        id              INT (auto increment)
        ip              VARCHAR(128)
        dns             VARCHAR(512)
        location        VARCHAR(256)
        function        VARCHAR(256)
        owner           VARCHAR(256)
        serial          VARCHAR(256)
        vendor          VARCHAR(256)
        model           VARCHAR(256)
        changelog       VARCHAR(256)
        build_docs      VARCHAR(256)

owner

        id              INT
        fname           VARCHAR(128)
        lname           VARCHAR(128)
        phone           VARCHAR(32)
        email           VARCHAR(256)
        location        VARCHAR(512)
        role            VARCHAR(128)
        group           VARCHAR(128)


services

        id              INT (auto increment)
        port            VARCHAR(5)
        svc_name        VARCHAR(256)
        protocol        VARCHAR(256)

nessus

        id              INT (auto increment)
        pluginID        INT
        pluginName      VARCHAR(512)
        pluginFamily    VARCHAR(128)
        v_pub_date      VARCHAR(128)
        cpe             VARCHAR(128)
        solution        BLOB
        risk_factor
        description
        p_pub_date
        cvss_vector
        synopsis
        plugin_type
        patch_pub_date
        plug_mod_date
        cvss_base_score
        cve
        bid
        xref
        plug_output
        plug_version

issues

        id              INT (auto increment)
        asset           INT
        nessus          INT
        org_risk_factor INT
        org_priority
        prop_solution   BLOB
        accepted        INT
        accepted_by     VARCHAR(128)
        false_positive  INT
        fp_reasoning    BLOB
        first_found     TIMESTAMP
        last_found      TIMESTAMP
        found_history   BLOB
        notes           BLOB
        owner           INT
        assigned_to     INT
        resolved        TIMESTAMP
        mitigated       TIMESTAMP
        status          INT

scan

        id
        timestamp
        tool_used

risk_factor

        id              INT
        rank            VARCHAR(16)

stats

        id
        time
        scans
        issues_outstanding
        issues_resolved
        issues_mitigated
        issues_fp
        crit
        med
        low
        info
        changes

status

        id
        desc
*/


echo "\r\nCritical\r\n";
  print_r($critvulnerabilities);


foreach ($critvulnerabilities as &$value) {

        $c_ip = $value['ip'];
        $c_dns = $value['dns'];
        $c_port = $value['port'];
        $c_svc_name = $value['svc_name'];
        $c_protocol = $value['protocol'];
        $c_pluginID = $value['pluginID'];
        $c_pluginName = $value['pluginName'];
        $c_pluginFamily = $value['pluginFamily'];
        $c_vuln_publication_date = $value['vuln_publication_date'];
        $c_cpe = $value['cpe'];
        $c_solution = $value['solution'];
        $c_risk_factor = $value['risk_factor'];
        $c_description = $value['description'];
        $c_plugin_publication_date = $value['plugin_publication_date'];
        $c_cvss_vector = $value['cvss_vector'];
        $c_synopsis = $value['synopsis'];
        $c_plugin_type = $value['plugin_type'];
        $c_patch_publication_date = $value['patch_publication_date'];
        $c_plugin_modification_date = 
$value['plugin_modification_date'];
        $c_cvss_base_score = $value['cvss_base_score'];
        $c_cve = $value['cve'];
        $c_bid = $value['bid'];
        $c_xref = $value['xref'];
        $c_plugin_output = $value['plugin_output'];
        $c_plugin_version = $value['plugin_version'];

        // test host table for host entry (ip + dns), add if doesn't 
exist

        // test generic vulnerability information, add if doesn't exist, 
mark if updated

        // test if issue already has been added, add if doesn't exist, 
tally if it does

                // test if false positive

}

echo "\r\nMedium\r\n";
  print_r($medvulnerabilities);

foreach ($medvulnerabilities as &$value) {

}

echo "\r\nLow\r\n";
  print_r($lowvulnerabilities);

foreach ($lowvulnerabilities as &$value) {

}

echo "\r\nInfo\r\n";
  print_r($infovulnerabilities);

foreach ($infovulnerabilties as &$value) {

}

//}
?>

