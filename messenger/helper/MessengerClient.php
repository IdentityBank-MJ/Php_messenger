<?php
# * ********************************************************************* *
# *                                                                       *
# *   Interface for IDB Messenger                                         *
# *   This file is part of messenger. This project may be found at:       *
# *   https://github.com/IdentityBank/Php_messenger.                      *
# *                                                                       *
# *   Copyright (C) 2020 by Identity Bank. All Rights Reserved.           *
# *   https://www.identitybank.eu - You belong to you                     *
# *                                                                       *
# *   This program is free software: you can redistribute it and/or       *
# *   modify it under the terms of the GNU Affero General Public          *
# *   License as published by the Free Software Foundation, either        *
# *   version 3 of the License, or (at your option) any later version.    *
# *                                                                       *
# *   This program is distributed in the hope that it will be useful,     *
# *   but WITHOUT ANY WARRANTY; without even the implied warranty of      *
# *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the        *
# *   GNU Affero General Public License for more details.                 *
# *                                                                       *
# *   You should have received a copy of the GNU Affero General Public    *
# *   License along with this program. If not, see                        *
# *   https://www.gnu.org/licenses/.                                      *
# *                                                                       *
# * ********************************************************************* *

################################################################################
# Namespace                                                                    #
################################################################################

namespace xmz\messenger;

################################################################################
# Use(s)                                                                       #
################################################################################

use Exception;

################################################################################
# Class(es)                                                                    #
################################################################################

class MessengerClient
{

    private $maxBufferSize = 4096;
    private $configuration = null;
    private $host = null;
    private $port = null;
    private $errors = [];

    private function setSecurity($sectionName)
    {
        if (!empty($this->configuration["${sectionName}Security"])) {
            $this->configuration["Security"] = $this->configuration["${sectionName}Security"];
        }
    }

    private static function checkEmailTo($to)
    {
        if (!is_array($to) && !empty($to)) {
            $to = [["email" => $to]];
        }

        return $to;
    }

    public function setConfiguration($configuration)
    {
        $this->configuration = $configuration;
    }

    public function getErrors()
    {
        return $this->errors;
    }

    public function slack($to, $message)
    {
        if (
            $this->configuration
            && !empty($this->configuration['slackHost'])
            && !empty($this->configuration['slackPort'])
        ) {
            $this->host = $this->configuration['slackHost'];
            $this->port = $this->configuration['slackPort'];
            $this->setSecurity('slack');
        }
        $request =
            [
                "type" => "communicator",
                "messageData" =>
                    [
                        "to" => $to,
                        "body" => $message
                    ]
            ];

        return $this->execute($request);
    }

    public function sms($to, $message)
    {
        if (
            $this->configuration
            && !empty($this->configuration['smsHost'])
            && !empty($this->configuration['smsPort'])
        ) {
            $this->host = $this->configuration['smsHost'];
            $this->port = $this->configuration['smsPort'];
            $this->setSecurity('sms');
        }
        $request =
            [
                "type" => "sms",
                "smsData" =>
                    [
                        "to" => $to,
                        "from" => 'IdentityBnk',
                        "body" => $message
                    ]
            ];

        return $this->execute($request);
    }

    public function email($to, $subject, $message, $cc = null, $bcc = null)
    {
        if (
            $this->configuration
            && !empty($this->configuration['emailHost'])
            && !empty($this->configuration['emailPort'])
        ) {
            $this->host = $this->configuration['emailHost'];
            $this->port = $this->configuration['emailPort'];
            $this->setSecurity('email');
        }
        $to = self::checkEmailTo($to);
        $cc = self::checkEmailTo($cc);
        $bcc = self::checkEmailTo($bcc);
        $request =
            [
                "type" => "email",
                "emailData" =>
                    [
                        "to" => $to,
                        "subject" => $subject,
                        "body" =>
                            [
                                'html' => $message
                            ]
                    ]
            ];
        if (!empty($cc)) {
            $request["emailData"]["cc"] = $cc;
        }
        if (!empty($bcc)) {
            $request["emailData"]["bcc"] = $bcc;
        }

        return $this->execute($request);
    }

    public function execute($request)
    {
        try {
            $request = json_encode($request);
            if (!empty($this->host)) {
                $this->host = gethostbyname($this->host);
            }

            if (empty($request) || empty($this->host) || empty($this->port)) {
                return null;
            }

            // ***
            $socket = socket_create(AF_INET, SOCK_STREAM, SOL_TCP);
            // ***

            if ($socket === false) {
                $this->errors[] = "socket_create() failed: reason: " . socket_strerror(socket_last_error());
            }

            // ***
            $result = socket_connect($socket, $this->host, $this->port);
            // ***

            if ($result === false) {
                $this->errors[] = "socket_connect() failed. Reason: ($result) " . socket_strerror(
                        socket_last_error($socket)
                    );
            }

            if (empty($this->configuration['Security'])) {
                $queryResult = $this->executeRequestNone($socket, $request);
            } elseif (strtoupper($this->configuration['Security']['type']) === 'TOKEN') {
                $queryResult = $this->executeRequestToken($socket, $request);
            } elseif (strtoupper($this->configuration['Security']['type']) === 'CERTIFICATE') {
                $queryResult = $this->executeRequestCertificate($socket, $request);
            } else {
                $queryResult = $this->executeRequestNone($socket, $request);
            }

            // ***
            socket_close($socket);
            // ***

            if (empty($this->errors)) {
                return $queryResult;
            }
        } catch (Exception $e) {
            error_log('Problem processing your query.');
            error_log(json_encode(['host' => $this->host, 'port' => $this->port]));
            if (!empty($e) and !empty($e->getMessage())) {
                error_log($e->getMessage());
            }
        }

        return null;
    }

    public function executeRequestNone($socket, $request)
    {
        $queryResult = null;
        try {
            socket_write($socket, $request, strlen($request));

            $queryResult = '';
            while ($result = socket_read($socket, $this->maxBufferSize)) {
                $queryResult .= $result;
            }
        } catch (Exception $e) {
            $queryResult = null;
        }

        return $queryResult;
    }

    public function executeRequestToken($socket, $request)
    {
        $queryResult = null;
        try {

            $dataChecksum = md5($request);
            $dataLength = strlen($request);
            $dataChecksumLength = strlen($dataChecksum);
            $size = $dataLength + $dataChecksumLength;
            $size = pack('P', $size);
            $token = $this->configuration['Security']['token'];
            $id = time();
            $id = pack('P', $id);
            $dataChecksumType = str_pad('MD5', 8);

            socket_write($socket, $token, strlen($token));
            socket_write($socket, $size, strlen($size));
            socket_write($socket, $id, strlen($id));
            socket_write($socket, $dataChecksumType, strlen($dataChecksumType));
            socket_write($socket, $dataChecksum, strlen($dataChecksum));
            socket_write($socket, $request, strlen($request));

            $token = '';
            while ($result = socket_read($socket, $this->configuration['Security']['tokenSizeBytes'])) {
                $token .= $result;
                if ($this->configuration['Security']['tokenSizeBytes'] <= strlen($token)) {
                    break;
                }
            }
            $size = '';
            while ($result = socket_read($socket, 8)) {
                $size .= $result;
                if (8 <= strlen($size)) {
                    break;
                }
            }
            if (!empty($size)) {
                $size = unpack('P', $size);
            }
            $id = '';
            while ($result = socket_read($socket, 8)) {
                $id .= $result;
                if (8 <= strlen($id)) {
                    break;
                }
            }
            if (!empty($id)) {
                $id = unpack('P', $id);
            }
            $checksumType = '';
            while ($result = socket_read($socket, 8)) {
                $checksumType .= $result;
                if (8 <= strlen($checksumType)) {
                    break;
                }
            }
            $checksumType = trim($checksumType);

            $queryResult = '';
            while ($result = socket_read($socket, $this->maxBufferSize)) {
                $queryResult .= $result;
                if ($size <= strlen($queryResult)) {
                    break;
                }
            }
            $checksum = substr($queryResult, 0, 32);
            $queryResult = substr($queryResult, 32);
            if (strtoupper($checksumType) === 'MD5') {
                $dataChecksum = md5($queryResult);
            } else {
                $dataChecksum = null;
            }
            if (strtolower($checksum) !== $dataChecksum) {
                $queryResult = null;
            }
        } catch (Exception $e) {
            $queryResult = null;
        }

        return $queryResult;
    }

    public function executeRequestCertificate($socket, $request)
    {
        $queryResult = null;
        try {
        } catch (Exception $e) {
            $queryResult = null;
        }

        return $queryResult;
    }
}

################################################################################
#                                End of file                                   #
################################################################################
