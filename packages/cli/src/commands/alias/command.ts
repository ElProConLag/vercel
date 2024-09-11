import { packageName } from '../../util/pkg-name';
import { limitOption, nextOption, yesOption } from '../../util/arg-common';

const listSubcommand = {
  name: 'ls',
  description: 'Show all aliases.',
  arguments: [],
  options: [
    {
      ...limitOption,
      description:
        'Number of results to return per page (default: 20, max: 100)',
      argument: 'NUMBER',
    },
    {
      ...nextOption,
      description: 'Show next page of results',
      argument: 'MS',
    },
  ],
  examples: [],
} as const;

const setSubcommand = {
  name: 'set',
  description: 'Create a new alias',
  arguments: [
    {
      name: 'deployment',
      required: true,
    },
    {
      name: 'alias',
      required: true,
    },
  ],
  options: [],
  examples: [],
} as const;

const removeSubcommand = {
  name: 'rm',
  description: 'Remove an alias using its hostname.',
  arguments: [
    {
      name: 'alias',
      required: true,
    },
  ],
  options: [
    {
      ...yesOption,
      description: 'Skip the confirmation prompt when removing an alias',
    },
  ],
  examples: [],
} as const;

export const aliasCommand = {
  name: 'alias',
  description: 'Interact with deployment aliases.',
  arguments: [
    {
      name: 'command',
      required: false,
    },
  ],
  subcommands: [listSubcommand, setSubcommand, removeSubcommand],
  options: [
    ...listSubcommand.options,
    ...setSubcommand.options,
    ...removeSubcommand.options,
    { name: 'json', shorthand: null, type: Boolean, deprecated: false },
  ],
  examples: [
    {
      name: 'Add a new alias to `my-api.vercel.app`',
      value: `${packageName} alias set api-ownv3nc9f8.vercel.app my-api.vercel.app`,
    },
    {
      name: 'Custom domains work as alias targets',
      value: `${packageName} alias set api-ownv3nc9f8.vercel.app my-api.com`,
    },
    {
      name: 'The subcommand `set` is the default and can be skipped. Protocols in the URLs are unneeded and ignored',
      value: `${packageName} alias api-ownv3nc9f8.vercel.app my-api.com`,
    },
  ],
} as const;
