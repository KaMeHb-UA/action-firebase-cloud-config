import { env } from 'node:process';
import { error, getInput, info } from '@actions/core';
import { load, dump } from 'js-yaml';

const CONFIG_ENV_PREFIX = 'config.';

function getConfigValues() {
    const values: Record<string, string> = {};
    for (const name in env) {
        if (name.startsWith(CONFIG_ENV_PREFIX)) {
            values[name.slice(CONFIG_ENV_PREFIX.length)] = env[name]!;
        }
    }
    return values;
}

function replaceAll(str: string, search: string, value: string) {
    while(true) {
        const nextStr = str.replace(search, value);
        if (nextStr === str) return str;
        str = nextStr;
    }
}

function setConfigValuesRecursively(config: Record<string, any>, values: Record<string, string>) {
    for (const i in config) {
        if (typeof config[i] === 'string') {
            for (const name in values) {
                config[i] = replaceAll(config[i], `\${${name}}`, values[name]);
            }
        } else if (typeof config[i] === 'object' && config[i]) {
            setConfigValuesRecursively(config[i], values);
        }
    }
}

export default () => {
    const config = load(getInput('config'));
    if (!config || typeof config !== 'object' || Array.isArray(config)) {
        error('Unknown config object. Should be YAML or JSON -serialized object');
    }
    info(`Loaded config:\n${dump(config)}`);
    const configValues = getConfigValues();
    info(`Loaded config values:\n${dump(configValues)}`);
    setConfigValuesRecursively(config as Record<string, any>, configValues);
    info(`Config with values:\n${dump(config)}`);
    return config as Record<string, any>;
}
