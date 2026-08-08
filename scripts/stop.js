const { execSync } = require('child_process');
const os = require('os');

const port = process.env.PORT || 3000;

try {
  if (os.platform() === 'win32') {
    execSync(`for /f "tokens=5" %a in ('netstat -aon ^| findstr :${port}') do taskkill /F /PID %a`, { stdio: 'ignore', shell: 'cmd.exe' });
  } else {
    execSync(`lsof -ti:${port} | xargs kill -9`, { stdio: 'ignore' });
  }
  console.log(`Stopped process on port ${port}`);
} catch (_) {
  console.log(`No process found on port ${port}`);
}
