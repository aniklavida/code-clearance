interface AppConfig {
  name: string;
  version: string;
}

function buildConfig(name: string, version: string): AppConfig {
  return { name, version };
}

const config = buildConfig('sample-app', '1.0.0');
console.log(config);
