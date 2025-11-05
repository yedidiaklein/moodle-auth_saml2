<?php
// This file is part of Moodle - http://moodle.org/
//
// Moodle is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// Moodle is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with Moodle.  If not, see <http://www.gnu.org/licenses/>.

/**
 * The class responsible for retrieving a user based on identifier.
 *
 * @package    auth_saml2
 * @author     Dmitrii Metelkin <dmitriim@catalyst-au.net>
 * @copyright  2021 Catalyst IT
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

namespace auth_saml2;

/**
 * The class responsible for retrieving a user based on identifier.
 *
 * @package    auth_saml2
 * @author     Dmitrii Metelkin <dmitriim@catalyst-au.net>
 * @copyright  2021 Catalyst IT
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */
class user_extractor {

    /**
     * Get extracted from DB user.
     *
     * @param string $fieldname Field name to search by.
     * @param string $fieldvalue Field value to search by.
     * @param bool $insensitive Whether to use case insensitive match.
     * @param bool $accentsensitive Whether to use accent sensitive match.
     * @param bool $numericinsensitive Whether to use numeric insensitive match (e.g., "012" = "12").
     *
     * @return mixed False, or A {$USER} object.
     */
    public static function get_user(
        string $fieldname,
        string $fieldvalue,
        bool $insensitive = false,
        bool $accentsensitive = true,
        bool $numericinsensitive = false
    ) {
        global $DB, $CFG;

        $user = false;
        $joins = '';
        $originalfieldvalue = $fieldvalue;

        // Debug logging function.
        $debuglog = function($msg) use ($CFG) {
            debugging('auth_saml2_user_extractor: ' . $msg, DEBUG_DEVELOPER);
            // Also log to file for easier debugging.
            $logfile = $CFG->dataroot . '/saml2.log';
            file_put_contents($logfile, date('Y-m-d H:i:s') . " - " . $msg . "\n", FILE_APPEND | LOCK_EX);
        };

        $debuglog("get_user called with: fieldname='$fieldname', fieldvalue='$originalfieldvalue', " .
                  "insensitive=" . ($insensitive ? 'true' : 'false') . ", " .
                  "accentsensitive=" . ($accentsensitive ? 'true' : 'false') . ", " .
                  "numericinsensitive=" . ($numericinsensitive ? 'true' : 'false'));

        // Handle numeric insensitive matching by normalizing numeric values.
        if ($numericinsensitive && is_numeric($fieldvalue)) {
            // Convert to number and back to string to remove leading zeros.
            $fieldvalue = (string)(float)$fieldvalue;
            $debuglog("Numeric insensitive: normalized '$originalfieldvalue' to '$fieldvalue'");
        }

        $params['fieldvalue'] = $fieldvalue;
        $params['mnethostid'] = $CFG->mnet_localhost_id;

        if (user_fields::is_custom_profile_field($fieldname)) {

            $fieldname = user_fields::get_field_short_name($fieldname);
            $debuglog("Custom profile field detected: '$fieldname'");

            $joins = " LEFT JOIN {user_info_field} f ON f.shortname = :fieldname ";
            $joins .= " LEFT JOIN {user_info_data} d ON d.fieldid = f.id AND d.userid = u.id ";

            if ($numericinsensitive && is_numeric($fieldvalue)) {
                // For numeric insensitive matching, use CAST to convert to numeric in SQL.
                $targetvalue = (float)$fieldvalue;
                // Use a regex to ensure the field contains only numeric data, then cast and compare.
                if ($DB->get_dbfamily() === 'postgres') {
                    $fieldsql = " AND d.data ~ '^[0-9]*\.?[0-9]+$' AND CAST(d.data AS DECIMAL) = CAST(:numericvalue AS DECIMAL)";
                } else if ($DB->get_dbfamily() === 'mysql') {
                    // MySQL: Use LTRIM to remove leading zeros and string comparison.
                    $normalizedvalue = ltrim($fieldvalue, '0') ?: '0';
                    $fieldsql = " AND (d.data = :fieldvalue OR LTRIM(d.data, '0') = :normalizedvalue)";
                    $params['normalizedvalue'] = $normalizedvalue;
                } else {
                    // Fallback: for other databases, try basic CAST (SQLite, MSSQL, etc.).
                    $fieldsql = " AND CAST(d.data AS REAL) = CAST(:numericvalue AS REAL)";
                }
                if ($DB->get_dbfamily() !== 'mysql') {
                    $params['numericvalue'] = (string)$targetvalue;
                }
                $debuglog("Custom field: Using SQL-based numeric insensitive matching for value: $targetvalue");
            } else {
                $fieldsql = " AND " . $DB->sql_equal('d.data', ':fieldvalue', !$insensitive, $accentsensitive);
                $debuglog("Custom field: Using regular SQL matching");
            }
            $params['fieldname'] = $fieldname;

        } else {
            // Check if requested field exists, required for Totara compatibility.
            $fields = array_merge(\core_user::AUTHSYNCFIELDS, ['id', 'username']);
            if (in_array($fieldname, $fields)) {
                $debuglog("Regular user field detected: '$fieldname'");
                if ($numericinsensitive && is_numeric($fieldvalue)) {
                    // For numeric insensitive matching, use CAST to convert to numeric in SQL.
                    $targetvalue = (float)$fieldvalue;
                    // Use a regex to ensure the field contains only numeric data, then cast and compare.
                    if ($DB->get_dbfamily() === 'postgres') {
                        $fieldsql = " AND u.$fieldname ~ '^[0-9]*\.?[0-9]+$' " .
                                   " AND CAST(u.$fieldname AS DECIMAL) = CAST(:numericvalue AS DECIMAL)";
                    } else if ($DB->get_dbfamily() === 'mysql') {
                        // MySQL: Use LTRIM to remove leading zeros and string comparison.
                        $normalizedvalue = ltrim($fieldvalue, '0') ?: '0';
                        $fieldsql = " AND (u.$fieldname = :fieldvalue OR LTRIM(u.$fieldname, '0') = :normalizedvalue)";
                        $params['normalizedvalue'] = $normalizedvalue;
                    } else {
                        // Fallback: for other databases, try basic CAST (SQLite, MSSQL, etc.).
                        $fieldsql = " AND CAST(u.$fieldname AS REAL) = CAST(:numericvalue AS REAL)";
                    }
                    if ($DB->get_dbfamily() !== 'mysql') {
                        $params['numericvalue'] = (string)$targetvalue;
                    }
                    $debuglog("Regular field: Using SQL-based numeric insensitive matching for value: $targetvalue");
                } else {
                    $fieldsql = " AND " . $DB->sql_equal('u.' . $fieldname, ':fieldvalue', !$insensitive, $accentsensitive);
                    $debuglog("Regular field: Using regular SQL matching");
                }
                $params['fieldname'] = $fieldname;
            } else {
                $debuglog("Field '$fieldname' not found in allowed fields");
            }
        }

        if (!empty($fieldsql)) {
            // Build the SQL query (numeric filtering now happens in SQL, not PHP).
            $sql = "SELECT u.id
                      FROM {user} u $joins
                     WHERE u.deleted <> 1
                       AND u.mnethostid = :mnethostid $fieldsql";

            $debuglog("SQL Query: $sql");
            $debuglog("SQL Params: " . json_encode($params));

            if ($records = $DB->get_records_sql($sql, $params)) {
                $debuglog("Found " . count($records) . " matching records from database");
                
                if (count($records) == 1) {
                    $record = reset($records);
                    $user = get_complete_user_data('id', $record->id);
                    $debuglog("SUCCESS: Found single matching user with ID {$record->id}");
                } else if (count($records) > 1) {
                    $debuglog("ERROR: Multiple matching records found, cannot determine unique user");
                } else {
                    $debuglog("No matching records found");
                }
            } else {
                $debuglog("No records returned from database query");
            }
        } else {
            $debuglog("No field SQL generated - check field name validity");
        }
        
        $debuglog("get_user returning: " . ($user ? "User ID {$user->id} ({$user->username})" : "false"));
        return $user;
    }
}
