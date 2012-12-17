// Reqs
var npcap = require('npcap');
var readline = require('readline');
var util = require('util');
var keypress = require('keypress');

// Variables
var version = '1.0';
var dev, mode, info, session;
info = {
    protocol: null,
    port: null,
    host: null,
    num: 0
};

var header = '//////////////////////';
console.log(header);
console.log('Welcome to JSniff '+version); // Greet the user
console.log(header);

// Select network device
var deviceList = '';
for (var i = 0; i < npcap.devs.length; i++) {
    deviceList += '\n'+(1+i)+') '+npcap.devs[i];
}
var rl = readline.createInterface(process.stdin, process.stdout);
rl.on('close', setup);
var prompt = '\n> ';
rl.question('Select your Network Device :-'+deviceList+prompt, askForMode); // Ask to select a Network Device

//setup();

function setup() {
    session = npcap.createSession(dev, mode, info); // session is a EventEmmiter
    if (!session) {
        console.error("Couldn't create a session");
        process.exit(-1);
    }
    session.on('close', function(stats) {
        console.log(stats);
    });
    // Star listening for the 'x' to stop the current process
    // listen for the "keypress" event
    // make `process.stdin` begin emitting "keypress" events
    keypress(process.stdin);
    process.stdin.on('keypress', function (ch, key) {
       if (key && key.name == 'x') {
            process.stdin.pause();
            session.stop();
            process.exit(0);
        }
    });

    process.stdin.setRawMode(true);
    process.stdin.resume();
    // Session created - start listening
    session.start(npcap.hexdump, info.num);
}

function askNumber(ans) {
    if (ans != '0') {
        info.host = ans;
    }
    rl.question('Number of packets to listen to :-'+prompt, function(ans) {
        info.num = parseInt(ans);
        rl.close();
    })
}

function askForHost(port) {
    if (port != '-1') {
        info.port = parseInt(port);
    }
    rl.question('Listen on host (0 for None)'+prompt, askNumber);
}

function takePort(ans) {
    if (ans == 'y') {
        rl.question('Enter port number :-'+prompt, askForHost);
    } else {
        askForHost('-1');
    }
}

function askForPort(protocol) {
    info.protocol = parseInt(protocol);
    if (info.protocol < 1 || info.protocol > 6) {
        console.error('Incorrect option for protocol');
        process.exit(-1);
    }
    rl.question('Do you want to listen on a specific port? [y/n]'+prompt, takePort);
}

function askForProto(deviceMode) {
    mode = parseInt(deviceMode);
    if (!mode || isNaN(mode) || mode < 1 || mode > 3) {
        console.error('Unrecognized mode');
        process.exit(-1);
    }
    var protoList = '1) Raw\n2) Ethernet\n3) TCP\n4) IP\n5) UDP\n6) Wlan';
    rl.question('Select the protocol :-\n'+protoList+prompt, askForPort);
}

function askForMode(device) {
    dev = npcap.devs[device-1]
    //Select mode
    var modeList = '1) None\n2) Promiscuous\n3) Monitor';
    rl.question('Select your Mode :-\n'+modeList+prompt, askForProto);
}