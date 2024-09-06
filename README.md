# Reverse Engineering an AquaForte WiFi Pond Pump

My dad bought this [AquaForte DM Vario S 20000 pond pump](https://www.aqua-forte.com/product/aquaforte-dm-vario-s-20000-pond-pump-with-wi-fi/) with WiFi connectivity, in the hope that I could connect it to the solar panels and automatically turn up the pump when the electricity production is high. 
Unfortunately, the app is anything but good and the pump itself is not controlled via the local network, but over a cloud. So I set myself the task of reverse engineering the pump controls. 

## 1. Portscan and Traffic

The scan revealed an open Port `12416/tcp`.

```bash
nmap -p- {device-ip}
```

I then ARP spoofed first the pump and then my phone (no idea if that was even necessary) ...

```bash
sudo arpspoof -i wlan0 -t {device-ip} {gateway-ip}
```

... dumped the traffic into a file ...

```bash
sudo tcpdump -i wlan0 host {device-ip} -w file.pcap  
```

... and used wireshark to read the pcap files.

### 1.1. Pump Traffic

The Pump traffic revealed the MQTT Topic `dev2app/{device-id}` and the Server `3.68.48.229`.

I used the App to set the pump to the following settings and read the traffic:

- switched off
- switched on
- Speed 47
- Speed 81
- Speed 30

I was able to receive 6 mqtt packets. 
5 of them were ‘Publish Message [dev2app/{device-id}]’. The other one was a MQTT Ping Request.
The source was the pump and the destination was the server mentioned above. 

The first MQTT packet, which should be the `off` command, had the following Message:

`00000003b20200009104101e0a64001418090400151f2f000000000164eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee00`

That are 564 e, so I will just abbreviate it to e{564}.

These are the 5 command packets I received:

```txt
OFF - `00000003b20200009104101e0a64001418090400151f2f000000000164 e{564} 00`

ON - `00000003b20200009104111e0a64001418090400151f2f000000000164 e{564} 00`

Speed 47 - `00000003b20200009104112f0a64001418090400151f2f000000000164 e{564} 00`

Speed 81 - `00000003b2020000910411510a64001418090400151f2f000000000164 e{564} 00`

Speed 30 - `00000003b20200009104111e0a64001418090400151f2f000000000164 e{564} 00`
```

Somewhat better visualised:

```txt
00000003b202000091041 0 1e 0a64001418090400151f2f000000000164 e{564} 00
00000003b202000091041 1 1e 0a64001418090400151f2f000000000164 e{564} 00
00000003b202000091041 1 2f 0a64001418090400151f2f000000000164 e{564} 00
00000003b202000091041 1 51 0a64001418090400151f2f000000000164 e{564} 00
00000003b202000091041 1 1e 0a64001418090400151f2f000000000164 e{564} 00
```

The Hex `1e` in the first command is Decimal `30`, which is the initial Speed the Pump was set to when I turned it off.

In the second command the `1e` can be seen again, but this time preceded by a `1` instead of a `0`.

In the remaining three commands you can recognise the `1` again, followed by the speeds I set in the App. Hex `2f` is Dec `47`, Hex `51` is Dec `81` and Hex 1e` is again Dec `30`.

Lets split the command into bytes.

```txt
00 00 00 03 b2 02 00 00 91 04 10 1e 0a 64 00 14 18 09 04 00 15 1f 2f 00 00 00 00 01 64 e{564} 00
```

So byte 11 should be the command to turn the pump on and off. `10` is off and `11` is on.

Followed by byte 12, which indicates the pump speed.


### 1.2. Phone App Traffic

The App traffic revealed several Domains:

- appmonitor.gizwits.com
- euaepapp.gizwits.com
- euapi.gizwits.com

The App also made some unencrypted requests to an API

```txt
GET /app/users/terms?locate=de HTTP/1.1
Host: euapi.gizwits.com
Content-Type: application/json
Connection: keep-alive
x-gizwits-user-token: {user-token}
Accept: */*
x-gizwits-application-id: {app-id}
Accept-Language: de-DE,de;q=0.9
Accept-Encoding: gzip, deflate
User-Agent: gizwitssuperapprn/104700000 CFNetwork/1498.700.2 Darwin/23.6.0
```

And it sent my phones data via a Post request to `http://euapi.gizwits.com/app/provision`

```json
{
  "phone_id": "{uuid}",
  "os": "iOS",
  "os_ver": "17.6.1",
  "sdk_version": "2.23.23.01613",
  "phone_model": "iPhone16,1"
}
```


## 2. API

From the traffic information, we now know that both the app and the pump communicate with Gizwits servers. Gizwits appears to be a manufacturer and operator of IOT devices and infrastructure.

The Documentation of their APIs can be seen here `https://docs.gizwits.com/en-us/cloud/OpenAPI.html`.

Thanks to the unencrypted request on `/app/users/terms`, I know my `user-token` and my `app-id`, and made a few requests.

### 2.1. Device Info

```bash
curl -X GET "https://euapi.gizwits.com/app/devices/{device-id}" -H "X-Gizwits-Application-Id: {app-id}" -H "X-Gizwits-User-token: {user-token}"
```

```json
{
  "remark": "",
  "protoc": 3,
  "wss_port": 8880,
  "ws_port": 8080,
  "did": "{device-id}",
  "port_s": 8883,
  "is_disabled": false,
  "proto_ver": "04",
  "product_key": "c6b30f30e4444e818d97cfac5b2a1e58",
  "port": 1883,
  "host": "eum2m.gizwits.com",
  "mac": "{mac}",
  "state_last_timestamp": 1725546725,
  "role": "special",
  "gw_did": null,
  "mesh_id": null,
  "is_online": true,
  "passcode": "{passcode}",
  "sleep_duration": 0,
  "product_name": "户外水泵",
  "is_low_power": false
}
```

`户外水泵` translates to `Outdoor water pump`.

No we also know the Product Key and the Passcode.

### 2.2. Online Log

```bash
curl -X GET "https://euapi.gizwits.com/app/devices/{device-id}/raw_data?type=online&start_time=1725477480&end_time=1725484860" -H "X-Gizwits-Application-Id: {app-id}" -H "X-Gizwits-User-token: {user-token}"
```

```json
{
  "meta": {
    "sort": "desc",
    "limit": 20,
    "end_time": 1725484860,
    "did": "{device-id}",
    "skip": 0,
    "start_time": 1725477480,
    "total": 1,
    "type": "online"
  },
  "objects": {
    "hits": {
      "total": 1,
      "objects": [
        {
          "ip": "{my-ip}",
          "type": "dev_online",
          "payload": {
            "keep_alive": 130
          },
          "timestamp": 1725478248
        }
      ]
    },
    "took": 117,
    "err_code": 0
  }
}
```

### 2.3. Cmd Log

Sadly, the query of the cmd log did not work. This would probably have helped a lot to understand how to control the pump.

```bash
curl -X GET "https://euapi.gizwits.com/app/devices/{device-id}/raw_data?type=cmd&start_time=1725477480&end_time=1725484860" -H "X-Gizwits-Application-Id: {app-id}" -H "X-Gizwits-User-token: {user-token}"
```

```json
{
  "error_message": "string indices must be integers",
  "error_code": 9008,
  "detail_message": null
}
```

I also tried `api.gizwits.com` instead of `euapi.gizwits.com`, but that just returns an error

```json
{
  "error_message": "token invalid!",
  "error_code": 9004,
  "detail_message": null
}
```

At least we now know that their systems are separated by region and that a user only ever exists in their region. Since I am in Germany, my user-token only exists on `euapi.gizwits.com`.

The only other `*api.gizwits.com` I found that returned `token invalid!` is `usapi`

The error `string indices must be integers` sounds a lot like Python.
When we open an API URL like `https://euapi.gizwits.com/app/devices` in a browser, we can see that they in fact use the Django REST framework, which is based on python.
So the error is very likely just a bug.

### 2.4. Datapoints

```bash
curl -X GET "https://euapi.gizwits.com/app/datapoint?product_key=c6b30f30e4444e818d97cfac5b2a1e58"
```

[Datapoints](datapoints.json).


## 3. Gizwits Protocol

While searching the internet for more documentation on how to control these Gizwits devices, I came across [this Github repo](https://github.com/Apollon77/node-ph803w/blob/main/PROTOCOL.md), which made me realise that all my work was almost pointless because someone had already done it before me and I was just too stupid to google it :c

At least the hex strings that I could read from the MQTT packets match the documentation of Apollon77.

### 3.1. Device Passcode

I followed Apollon77's tutorial and send `00 00 00 03 03 00 00 06` to the pump.

```bash
echo "00 00 00 03 03 00 00 06" | xxd -r -p | ncat 10.0.5.51 12416
```

I recieved my passcode as an ASCII String.

### 3.2. Login

I tried to login, but I never got an answer. I tried two ways of sending the passcode to the device, but neither of them worked.

```bash
echo "00 00 00 03 0f 00 00 08 00 0a PASSCODE" | xxd -r -p | ncat {device-ip} 12416
```

And the Hex version, where I basically translated every ASCII letter of the passcode into Hex.

```bash
echo "00 00 00 03 0f 00 00 08 00 0a xx xx xx xx xx xx xx xx xx xx" | xxd -r -p | ncat {device-ip} 12416
```

I sometimes got an answer, but it was just a empty String.

### 3.3. WiFi Module Information

```bash
echo "00 00 00 03 03 00 00 13" | xxd -r -p | ncat {device-ip} 12416
```

It returned `W00ESP82604020B30030000010303000000000002 c6b30f30e4444e818d97cfac5b2a1e58` in ASCII.

Translated to Hex so I can compare it with Apollon77's table in chapter [13/14](https://github.com/Apollon77/node-ph803w/blob/main/PROTOCOL.md#1314-wifi-module-information-tcp):

`57` - ?? `W`

`30 30 45 53 50 38 32 36` - Wifi hardware version `00ESP826`

`30 34 30 32 30 42 33 30` - Wifi software version `04020B30`

`30 33 30 30 30 30 30 31` - MCU hardware version `03000001`

`30 33 30 33 30 30 30 30` - MCU software version `03030000`

`30 30 30 30 30 30 30 32` - p0 protocol payload version `00000002`

` ` - ?? `Space`

`20 63 36 62 33 30 66 33 30 65 34 34 34 34 65 38 31 38 64 39 37 63 66 61 63 35 62 32 61 31 65 35 38` - Product Key `c6b30f30e4444e818d97cfac5b2a1e58`


### 3.4. Data.js

With Apollon77's example `data.js` script I recieved 

```json
Data: {
  "binFlags1":"11",
  "binFlags2":"10001",
  "ph":76.9,
  "redox":23600,
  "phOutlet":true,
  "redoxOutlet":false
}
```



The value names are obviously wrong, since this script was written for a completely different device, but at least the pump responded.  
His `discovery.js` script also recognized the pump in my network.

## 4. Control Device

Apollon77 states that the p0 protocol takes `01` to control the device, and `04` for the device to report its status.

Let's take a look at the MQTT Packets from the pump again:

```txt
00000003 b202000091 04 10 1e 0a64001418090400151f2f000000000164 e{564} 00
00000003 b202000091 04 11 1e 0a64001418090400151f2f000000000164 e{564} 00
00000003 b202000091 04 11 2f 0a64001418090400151f2f000000000164 e{564} 00
00000003 b202000091 04 11 51 0a64001418090400151f2f000000000164 e{564} 00
00000003 b202000091 04 11 1e 0a64001418090400151f2f000000000164 e{564} 00
```

I thought maybe `04` indicates that the pump reports its state to the server, `10` means the state of the pump (on/off) and `1e` is the pump speed.

So maybe I could use these 3 numbers to control the pump with the `Raw instructions` over the Gizwitz API. But instead of `04` we need `01` because we want to control the device.

Hex 01 = Dec 1, Hex 10 = Dec 16, Hex 1e = Dec 30

```bash
curl -X POST "https://euapi.gizwits.com/app/control/{device-id}" \
-H "X-Gizwits-Application-Id: {app-id}" \
-H "X-Gizwits-User-token: {user-token}" \
-d '{"raw": [1,16,30]}'
```

As repsone I got `{}` and the pump did not turn off.


## 5. Protocol Code

The following Code snippets are from [xuhongv's](https://github.com/xuhongv) implementation of the Gizwits protocol.
 
- [gizwits_protocol.h](https://raw.githubusercontent.com/xuhongv/StudyInEsp8266/master/Gizkit_soc_pet/app/Gizwits/gizwits_protocol.h)
- [gizwits_protocol.c](https://raw.githubusercontent.com/xuhongv/StudyInEsp8266/master/Gizkit_soc_pet/app/Gizwits/gizwits_protocol.c) 

```C
/** Corresponding to the protocol "4.10 WiFi module control device" in the flag " attr_flags" */ 

typedef struct {
  uint8_t flagLED_OnOff:1;
  uint8_t flagLED_Color:1;
  uint8_t flagLED_R:1;
  uint8_t flagLED_G:1;
  uint8_t flagLED_B:1;
  uint8_t flagMotor_Speed:1;
} attrFlags_t;
```

Every Flag is 1 bit, so the entire attrFlags_t is only 1 Byte long!

```C
/** Corresponding protocol "4.10 WiFi module control device" in the data value "attr_vals" */

typedef struct {
  uint8_t wBitBuf[COUNT_W_BIT];
  uint8_t valueLED_R;
  uint8_t valueLED_G;
  uint8_t valueLED_B;
  uint8_t valueMotor_Speed;
} attrVals_t;
```

```C
/** The flag "attr_flags (1B)" + data value "P0 protocol area" in the corresponding protocol "4.10 WiFi module control device"attr_vals(6B)" */ 

typedef struct {
    attrFlags_t attrFlags;
    attrVals_t  attrVals;
} gizwitsIssued_t;
```

