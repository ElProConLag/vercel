import { packageName } from '../../util/pkg-name';
import { confirmOption, yesOption } from '../../util/arg-common';

const connectSubcommand = {
  name: 'connect',
  description:
    'Connect your Vercel Project to your Git repository or provide the remote URL to your Git repository',
  arguments: [
    {
      name: 'git url',
      required: false,
    },
  ],
  options: [yesOption, { ...confirmOption, deprecated: true }],
  examples: [],
} as const;

const disconnectSubcommand = {
  name: 'disconnect',
  description: 'Disconnect the Git provider repository from your project',
  arguments: [],
  options: [],
  examples: [],
} as const;

export const gitCommand = {
  name: 'git',
  description: 'Manage your Git provider connections.',
  arguments: [
    {
      name: 'command',
      required: true,
    },
  ],
  subcommands: [connectSubcommand, disconnectSubcommand],
  options: [...connectSubcommand.options, ...disconnectSubcommand.options],
  examples: [
    {
      name: 'Connect your Vercel Project to your Git repository defined in your local .git config',
      value: `${packageName} git connect`,
    },
    {
      name: 'Connect your Vercel Project to a Git repository using the remote URL',
      value: `${packageName} git connect https://github.com/user/repo.git`,
    },
    {
      name: 'Disconnect the Git provider repository',
      value: `${packageName} git disconnect`,
    },
  ],
} as const;
