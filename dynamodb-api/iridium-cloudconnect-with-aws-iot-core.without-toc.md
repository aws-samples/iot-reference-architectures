# Iridium CloudConnect with AWS IoT Core

<!-- toc -->

## WARNING!

This architecture will send and receive SBD messages from Iridium CloudConnect. Sending messages will incur charges from
your airtime/service provider. Received messages will be put into DynamoDB but they will be erased if the stack is
deleted and the table is not backed up.

**Do not use this in a production environment without proper planning and testing!**

## What is this document?

This document is a supplement to the [SQS to DynamoDB with IoT Core based API](README.md) reference architecture. It
shows how this architecture can be integrated into a system that communicates with Iridium Short Burst Data (SBD)
devices using IoT Core.

## How does this differ from the baseline reference architecture?

To use this architecture you must be using the Iridium CloudConnect Quick Start. That Quick Start creates SQS queues for
mobile originated (MO) messages and mobile terminated (MT) messages. This architecture uses those SQS queues (called
ICCMO.fifo and ICCMT.fifo, respectively) instead of creating its own queues. It also sets the `UUID_NAME`
to `data.mo_header.imei` and `MESSAGE_ID_NAME` to `data.mo_header.cdr_reference` automatically so it will handle SBD
inbound messages automatically.

## How do I launch it?

Run the `./iridium-sbd-deploy.sh` script to deploy this stack.

Run the `./iridium-sbd-destroy.sh` script to destroy this stack.

**NOTE:** Destroying this stack **will not** remove the SQS queues created by the Iridium CloudConnect Quick Start but
it **will** remove the DynamoDB table. Make sure you have backed up the DynamoDB table if you need the data in it before
destroying this stack.

## How do I receive an SBD message from a device?

In this document we provide AT commands that have been tested on Iridium Edge devices to send messages. If your device
is not an Iridium Edge device you should first check to make sure that the AT commands are the same. If they are not you
will have to adapt the commands to your specific environment.

### Iridium Edge kit commands to send a message

We will send the text message `Test12345` from the Iridium Edge kit in this example. This message is less than 10 bytes
since that is the standard billing increment we have seen in SBD deployments. If you send a larger message you will
likely be charged for two payloads.

The AT command to queue this message is:

```
AT+SBDWT=Test12345
```

After sending this command to the device you should receive an `OK` response. At this point the message is queued but is
not sent.

The AT command to attempt to send the message is:

```
AT+SBDI
```

After sending this command you should see a response that looks similar to this:

```
+SBDI: A, B, C, D, E, F
```

`A` is known as the `MO status` field. It will be `1` if the message was sent successfully. It will be `2` if it could
not be sent. If it could not be sent it will still be queued and you can attempt the `AT+SBDI` command again.

**NOTE:** If the `MO status` is `0` then it means the device didn't have a message queued to send. This can happen if a
message is queued with `AT+SBDWT` but the device is powered off before it is sent. If this happens the message needs to
be queued again.

`B` is known as the `MOMSN` field. This is the Mobile Originated Message Sequence Number. It is a number assigned by the
device to each outbound message that can range from 0 to 65535. It will wrap around back to 0 after 65535.

`C` is known as the `MT status` field. It will be `1` if a message was received successfully. It will be `2` if no
message could be received due to a connection issue.

`D` is known as the `MTMSN` field. This is the Mobile Terminated Message Sequence Number. It is a number assigned by the
device to each inbound message that can range from 0 to 65535. It will wrap around back to 0 after 65535.

`E` is known as the `MT length` field. This is the length of the received message in bytes. It will be `0` if no message
was received.

`F` is known as the `MT queued` field. This is the number of mobile terminated messages waiting to be delivered to the
device. It will be `0` if no messages are waiting to be delivered. If it is greater than `0` you will need to issue
additional `AT+SBDI` commands to receive them.

**NOTE:** Messages are not saved on the device. They must be read with the `AT+SBDRT` command before another `AT+SBDI`
command is sent or they will be lost.

### What to expect in the ICCMO.fifo queue

**NOTE:** After this stack is launched messages will only be in the `ICCMO.fifo` queue for a short period of time. If
you do not see this message in the queue it may have already been moved to DynamoDB.

After sending the test message above a message will be put into the `ICCMO.fifo` queue similar to this:

```json
{
  "api_version": 1,
  "data": {
    "mo_header": {
      "cdr_reference": -1170003805,
      "session_status_int": 0,
      "session_status": "No error.",
      "momsn": 1483,
      "mtmsn": 124,
      "imei": "301234123412341",
      "time_of_session": "2021-05-22 00:20:13"
    },
    "payload": "546573743132333435"
  }
}
```

The `payload` field is hex encoded so this string represents the following byte array:

```
0x54, 0x65, 0x73, 0x74, 0x31, 0x32, 0x33, 0x34, 0x35
```

Which translates back to our original message `Test12345`.

### What to expect in IoT Core

After the message is taken out of SQS it will be stored in DynamoDB and then a notification message will be published to
IoT Core. The notification message for this example message will be on the following topic:

```
notification/301234123412341
```

The `301234123412341` value is the IMEI of the device that sent the message.

The payload of the message for this example message looks like this:

```json
{
  "uuid": "301234123412341",
  "messageId": "1621642815475-e4770a69-0e5a-4c28-b1e9-1e3143a6afb0"
}
```

The `uuid` field is the IMEI again. The `messageId` field is a Unix epoch milliseconds timestamp followed by a dash `-`
and a UUID. This is done so that the order that the messages were received can be maintained and messages arriving at
the same millisecond will always have a unique ID.

Applications that would like to be notified when a message arrives from a device can set up
a [topic rule](https://docs.aws.amazon.com/iot/latest/developerguide/iot-rules.html) to monitor this topic. With a
separate topic rule for each downstream application they can all be notified independently so there is no coupling
between separate downstream applications.

### What to expect in the DynamoDB table

The DynamoDB table holds all of the received messages. The entry in the DynamoDB table for this example message looks
like this:

Simplified JSON:

```json
{
  "body": {
    "api_version": 1,
    "data": {
      "mo_header": {
        "cdr_reference": -1170003805,
        "imei": "301234123412341",
        "momsn": 1483,
        "mtmsn": 124,
        "session_status": "No error.",
        "session_status_int": 0,
        "time_of_session": "2021-05-22 00:20:13"
      },
      "payload": "546573743132333435"
    }
  },
  "messageId": "1621642815475-e4770a69-0e5a-4c28-b1e9-1e3143a6afb0",
  "uuid": "301234123412341"
}
```

DynamoDB JSON:

```json
{
  "body": {
    "M": {
      "api_version": {
        "N": "1"
      },
      "data": {
        "M": {
          "mo_header": {
            "M": {
              "cdr_reference": {
                "N": "-1170003805"
              },
              "imei": {
                "S": "301234123412341"
              },
              "momsn": {
                "N": "1483"
              },
              "mtmsn": {
                "N": "124"
              },
              "session_status": {
                "S": "No error."
              },
              "session_status_int": {
                "N": "0"
              },
              "time_of_session": {
                "S": "2021-05-22 00:20:13"
              }
            }
          },
          "payload": {
            "S": "546573743132333435"
          }
        }
      }
    }
  },
  "messageId": {
    "S": "1621642815475-e4770a69-0e5a-4c28-b1e9-1e3143a6afb0"
  },
  "uuid": {
    "S": "301234123412341"
  }
}
```

## How do I send an SBD message to a device?

In this document we provide AT commands that have been tested on Iridium Edge devices to receive messages. If your
device is not an Iridium Edge device you should first check to make sure that the AT commands are the same. If they are
not you will have to adapt the commands to your specific environment.

### Iridium Edge kit commands to receive a message

We will send the text message `Test12345` to the Iridium Edge kit in this example. This message is less than 10 bytes
since that is the standard billing increment we have seen in SBD deployments. If you send a larger message you will
likely be charged for two payloads.

The command to send the message via AWS IoT Core to the Iridium Edge kit is:

```
./iot-send-message.sh 301234123412341 301234123412341 Test12345
```

The `301234123412341` value is the IMEI of the device that sent the message.

The `iot-send-message.sh` script takes a sender and a recipient UUID, respectively. Iridium SBD only cares about the
recipient UUID we simply use the same value in both places. In a production system this could be adapted to provide
permissions that only allow certain devices to talk to each other. The current system allows messages to be sent from
any sender to any recipient.

The send request for this example message will be on the following topic:

```
request/send/301234123412341/301234123412341
```

The send payload for this example message should be similar to this:

```json
{
  "token": "D93F0B78-FBDB-4C35-B9A2-C15635031D4E",
  "hex_payload": "546573743132333435"
}
```

The send response for this example message will be on the following topic:

```
response/send/301234123412341/301234123412341
```

The send response for this example message should be similar to this:

```json
{
  "token": "D93F0B78-FBDB-4C35-B9A2-C15635031D4E",
  "sqs_message_id": "58a40239-4ef7-4038-8636-4643da7fb605"
}
```

**NOTE:** An application sending a message through IoT Core should assume that if it did not receive a response on the
response topic that the message needs to be resent.

### What to expect in the ICCMT.fifo queue

**NOTE:** Messages will only be in the `ICCMT.fifo` queue for a short period of time. If you do not see this message in
the queue it may have already been picked up by Iridium CloudConnect.

After sending the test message above a message will be put into the `ICCMT.fifo` queue similar to this:

```json
{
  "message": "546573743132333435",
  "client_message_id": 1296242511,
  "imei": "301234123412341"
}
```

The `payload` field is hex encoded so this string represents the following byte array:

```
0x54, 0x65, 0x73, 0x74, 0x31, 0x32, 0x33, 0x34, 0x35
```

Which translates back to our original message `Test12345`.

### What to expect in the ICCMTConfirmation.fifo queue (successful messages)

After the message is taken out of SQS by Iridium CloudConnect it will be validated to make sure that it conforms to the
expected format, that the device IMEI is configured by the GSS to receive messages from your AWS account, and then
queued in the network to be sent to the device when it initiates an SBD session.

After sending the test message above a message will be put into the `ICCMTConfirmation.fifo` queue, if it was successful, similar to this:

```json
{
  "mt_message_id": "124036",
  "unique_client_message_id": 1296242511,
  "imei": "301234123412341",
  "auto_id_reference": 805827617,
  "mt_message_status": 3
}
```

The `301234123412341` value is the IMEI of the device that sent the message.

### What to expect in the ICCMTErrors.fifo queue (unsuccessful messages)

In the event that Iridium CloudConnect can not process a message in the `ICCMT.fifo` queue it will put an error message into the `ICCMTErrors.fifo` queue. The only error we have tested so far is sending a message to an IMEI that is not in our account. There are other error types but they are not documented here.

If the user does not have permission to send a message to the specified IMEI, the specified IMEI doesn't exist, or the device does not have an active airtime agreement the error will look like this:

```
Errors for message 124038 : Alert: IMEI 301234123412341 is not owned by customer 999999 or device is not active.
```

**NOTE:** These error messages are plain text. They are not JSON payloads.
