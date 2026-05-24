require('dotenv').config();

const {
    Client,
    GatewayIntentBits,
    PermissionsBitField,
    ChannelType,
    EmbedBuilder,
    AuditLogEvent
} = require('discord.js');

const axios = require('axios');

// ================= CLIENT =================

const client = new Client({
    intents: [
        GatewayIntentBits.Guilds,
        GatewayIntentBits.GuildMembers,
        GatewayIntentBits.GuildMessages,
        GatewayIntentBits.MessageContent,
        GatewayIntentBits.GuildWebhooks
    ]
});

// ================= SETTINGS =================

const WHITELIST_ROLE_ID = '1506126787023998976';

const GITHUB_OWNER = 'scpenthuasiast-dev';
const GITHUB_REPO = 'Anti-Raid-Bot';

const JOIN_LIMIT = 5;
const JOIN_TIME = 10000;

const MASS_MENTION_LIMIT = 5;

const ACCOUNT_AGE_LIMIT = 1000 * 60 * 60 * 24 * 3;

const CHANNEL_NUKE_LIMIT = 5;
const CHANNEL_NUKE_TIME = 10000;

const BOT_VERSION = '1.0.0';

// ================= VARIABLES =================

let joins = [];
let raidMode = false;

let channelActions = {};

// ================= READY =================

client.once('ready', async () => {

    console.log(`${client.user.tag} is online.`);

    const commands = [
        {
            name: 'lockdown',
            description: 'Lock the entire server'
        },
        {
            name: 'unlockdown',
            description: 'Unlock the entire server'
        },
        {
            name: 'raidmode',
            description: 'Enable raid mode manually'
        },
        {
            name: 'unraidmode',
            description: 'Disable raid mode manually'
        },
        {
            name: 'changelog',
            description: 'View latest bot updates'
        },
        {
            name: 'botinfo',
            description: 'View bot information'
        }
    ];

    const guild = client.guilds.cache.first();

    if (guild) {

        await guild.commands.set(commands);

        console.log(
            'Guild slash commands registered.'
        );
    }

    const updateChannel =
        client.channels.cache.find(
            c => c.name === 'bot-updates'
        );

    if (updateChannel) {

        const embed = new EmbedBuilder()
            .setTitle('🛠️ Bot Started')
            .setColor('Blue')
            .setDescription(
                `Version: ${BOT_VERSION}\nStatus: Online`
            )
            .addFields({
                name: 'Features',
                value:
                    '• Raid Protection\n' +
                    '• Lockdown System\n' +
                    '• Alt Detection\n' +
                    '• Webhook Protection\n' +
                    '• Anti Channel Nuke\n' +
                    '• GitHub Changelog\n' +
                    '• Mass Mention Protection'
            })
            .setTimestamp();

        updateChannel.send({
            embeds: [embed]
        });

    }

});

// ================= SLASH COMMANDS =================

client.on(
    'interactionCreate',
    async interaction => {

        if (
            !interaction.isChatInputCommand()
        ) return;

        // ===== PERMISSION CHECK =====

        if (
            !interaction.member.permissions.has(
                PermissionsBitField.Flags.Administrator
            )
        ) {

            return interaction.reply({
                content:
                    '❌ You do not have permission.',
                ephemeral: true
            });

        }

        const logChannel =
            interaction.guild.channels.cache.find(
                c =>
                    c.name === 'logs' ||
                    c.name === 'mod-logs'
            );

        const everyoneRole =
            interaction.guild.roles.everyone;

        // ================= LOCKDOWN =================

        if (
            interaction.commandName ===
            'lockdown'
        ) {

            interaction.guild.channels.cache.forEach(
                async channel => {

                    try {

                        if (
                            channel.type ===
                            ChannelType.GuildText
                        ) {

                            await channel.permissionOverwrites.edit(
                                everyoneRole,
                                {
                                    SendMessages: false
                                }
                            );

                        }

                    } catch (err) {}

                }
            );

            const embed =
                new EmbedBuilder()
                    .setTitle(
                        '🔒 SERVER LOCKDOWN ENABLED'
                    )
                    .setColor('Red')
                    .setDescription(
                        `Enabled by ${interaction.user.tag}`
                    )
                    .setTimestamp();

            if (logChannel) {

                logChannel.send({
                    content: '@everyone',
                    embeds: [embed]
                });

            }

            return interaction.reply({
                content:
                    '✅ Server locked.',
                ephemeral: true
            });

        }

        // ================= UNLOCKDOWN =================

        if (
            interaction.commandName ===
            'unlockdown'
        ) {

            interaction.guild.channels.cache.forEach(
                async channel => {

                    try {

                        if (
                            channel.type ===
                            ChannelType.GuildText
                        ) {

                            await channel.permissionOverwrites.edit(
                                everyoneRole,
                                {
                                    SendMessages: null
                                }
                            );

                        }

                    } catch (err) {}

                }
            );

            const embed =
                new EmbedBuilder()
                    .setTitle(
                        '🔓 SERVER LOCKDOWN DISABLED'
                    )
                    .setColor('Green')
                    .setDescription(
                        `Disabled by ${interaction.user.tag}`
                    )
                    .setTimestamp();

            if (logChannel) {

                logChannel.send({
                    embeds: [embed]
                });

            }

            return interaction.reply({
                content:
                    '✅ Server unlocked.',
                ephemeral: true
            });

        }

        // ================= RAIDMODE =================

        if (
            interaction.commandName ===
            'raidmode'
        ) {

            raidMode = true;

            return interaction.reply({
                content:
                    '🚨 Raid mode enabled.',
                ephemeral: true
            });

        }

        // ================= UNRAIDMODE =================

        if (
            interaction.commandName ===
            'unraidmode'
        ) {

            raidMode = false;

            return interaction.reply({
                content:
                    '✅ Raid mode disabled.',
                ephemeral: true
            });

        }

        // ================= CHANGELOG =================

        if (
            interaction.commandName ===
            'changelog'
        ) {

            try {

                const response =
                    await axios.get(
                        `https://api.github.com/repos/${GITHUB_OWNER}/${GITHUB_REPO}/commits`
                    );

                const commits =
                    response.data.slice(0, 5);

                const formatted =
                    commits
                        .map(commit => {

                            return (
                                `• ${commit.commit.message}\n` +
                                `By: ${commit.commit.author.name}`
                            );

                        })
                        .join('\n\n');

                const embed =
                    new EmbedBuilder()
                        .setTitle(
                            '🛠️ Latest Bot Updates'
                        )
                        .setColor('Blue')
                        .setDescription(
                            formatted
                        )
                        .setFooter({
                            text:
                                'Powered by GitHub'
                        })
                        .setTimestamp();

                return interaction.reply({
                    embeds: [embed]
                });

            } catch (err) {

                console.log(err);

                return interaction.reply({
                    content:
                        '❌ Failed to fetch changelog.',
                    ephemeral: true
                });

            }

        }

        // ================= BOTINFO =================

        if (
            interaction.commandName ===
            'botinfo'
        ) {

            const embed =
                new EmbedBuilder()
                    .setTitle(
                        '🤖 Bot Information'
                    )
                    .setColor('Blue')
                    .addFields(
                        {
                            name: 'Version',
                            value:
                                BOT_VERSION
                        },
                        {
                            name: 'Servers',
                            value:
                                `${client.guilds.cache.size}`
                        },
                        {
                            name: 'Ping',
                            value:
                                `${client.ws.ping}ms`
                        },
                        {
                            name: 'Raid Mode',
                            value:
                                raidMode
                                    ? 'Enabled'
                                    : 'Disabled'
                        }
                    )
                    .setTimestamp();

            return interaction.reply({
                embeds: [embed]
            });

        }

    }
);

// ================= MEMBER JOIN =================

client.on(
    'guildMemberAdd',
    async member => {

        const logChannel =
            member.guild.channels.cache.find(
                c =>
                    c.name === 'logs' ||
                    c.name === 'mod-logs'
            );

        const accountAge =
            Date.now() -
            member.user.createdTimestamp;

        // ================= ALT DETECTOR =================

        const flags = [];

        if (
            accountAge <
            1000 *
                60 *
                60 *
                24 *
                7
        ) {

            flags.push('New Account');

        }

        if (!member.user.avatar) {

            flags.push(
                'No Profile Picture'
            );

        }

        if (
            member.user.username
                .toLowerCase()
                .includes('discord')
        ) {

            flags.push(
                'Suspicious Username'
            );

        }

        if (flags.length >= 2) {

            try {

                await member.ban({
                    reason:
                        'Alt account detected'
                });

                if (logChannel) {

                    logChannel.send({
                        content:
                            `🚨 ALT ACCOUNT BANNED\n` +
                            `User: ${member.user.tag}\n` +
                            `Flags: ${flags.join(', ')}`
                    });

                }

            } catch (err) {

                console.log(err);

            }

            return;

        }

        // ================= ACCOUNT TOO NEW =================

        if (
            accountAge <
            ACCOUNT_AGE_LIMIT
        ) {

            try {

                await member.kick(
                    'Account too new'
                );

                if (logChannel) {

                    logChannel.send({
                        content:
                            `⚠️ Suspicious account kicked: ${member.user.tag}`
                    });

                }

            } catch (err) {

                console.log(err);

            }

            return;

        }

        // ================= RAID DETECTION =================

        joins.push(Date.now());

        joins = joins.filter(
            time =>
                Date.now() - time <
                JOIN_TIME
        );

        if (
            joins.length >=
                JOIN_LIMIT &&
            !raidMode
        ) {

            raidMode = true;

            const everyoneRole =
                member.guild.roles
                    .everyone;

            member.guild.channels.cache.forEach(
                async channel => {

                    try {

                        if (
                            channel.type ===
                            ChannelType.GuildText
                        ) {

                            await channel.permissionOverwrites.edit(
                                everyoneRole,
                                {
                                    SendMessages: false
                                }
                            );

                        }

                    } catch (err) {}

                }
            );

            const embed =
                new EmbedBuilder()
                    .setTitle(
                        '🚨 RAID DETECTED'
                    )
                    .setColor('DarkRed')
                    .setDescription(
                        `Detected ${joins.length} joins in ${JOIN_TIME / 1000} seconds.\n\nServer automatically locked.`
                    )
                    .setTimestamp();

            if (logChannel) {

                logChannel.send({
                    content:
                        '@everyone',
                    embeds: [embed]
                });

            }

        }

    }
);

// ================= MASS MENTION PROTECTION =================

client.on(
    'messageCreate',
    async message => {

        if (!message.guild) return;
        if (message.author.bot)
            return;

        if (
            message.member.roles.cache.has(
                WHITELIST_ROLE_ID
            )
        ) return;

        const logChannel =
            message.guild.channels.cache.find(
                c =>
                    c.name === 'logs' ||
                    c.name === 'mod-logs'
            );

        if (
            message.mentions.users.size >=
            MASS_MENTION_LIMIT
        ) {

            try {

                await message.delete();

                await message.member.ban({
                    reason:
                        'Mass mention spam'
                });

                if (logChannel) {

                    logChannel.send({
                        content:
                            `🚨 ${message.author.tag} was banned for mass mentions.`
                    });

                }

            } catch (err) {

                console.log(err);

            }

        }

    }
);

// ================= WEBHOOK PROTECTION =================

client.on(
    'webhooksUpdate',
    async channel => {

        try {

            const logs =
                await channel.guild.fetchAuditLogs(
                    {
                        limit: 1,
                        type:
                            AuditLogEvent.WebhookCreate
                    }
                );

            const entry =
                logs.entries.first();

            if (!entry) return;

            const {
                executor
            } = entry;

            const member =
                await channel.guild.members.fetch(
                    executor.id
                );

            if (!member) return;

            if (
                member.roles.cache.has(
                    WHITELIST_ROLE_ID
                )
            ) return;

            await member.ban({
                reason:
                    'Unauthorized webhook creation'
            });

            const webhooks =
                await channel.fetchWebhooks();

            for (const webhook of webhooks.values()) {

                try {

                    await webhook.delete();

                } catch (err) {}

            }

            const logChannel =
                channel.guild.channels.cache.find(
                    c =>
                        c.name === 'logs' ||
                        c.name === 'mod-logs'
                );

            if (logChannel) {

                logChannel.send({
                    content:
                        `🚨 ${executor.tag} was banned for webhook abuse.`
                });

            }

        } catch (err) {

            console.log(err);

        }

    }
);

// ================= ANTI CHANNEL NUKE =================

async function handleChannelNuke(
    guild,
    executor
) {

    try {

        const member =
            await guild.members.fetch(
                executor.id
            );

        if (!member) return;

        if (
            member.roles.cache.has(
                WHITELIST_ROLE_ID
            )
        ) return;

        if (
            !channelActions[
                executor.id
            ]
        ) {

            channelActions[
                executor.id
            ] = [];

        }

        channelActions[
            executor.id
        ].push(Date.now());

        channelActions[
            executor.id
        ] =
            channelActions[
                executor.id
            ].filter(
                time =>
                    Date.now() - time <
                    CHANNEL_NUKE_TIME
            );

        if (
            channelActions[
                executor.id
            ].length >=
            CHANNEL_NUKE_LIMIT
        ) {

            const rolesToRemove =
                member.roles.cache.filter(
                    role =>
                        role.id !== guild.id
                );

            await member.roles.remove(
                rolesToRemove
            );

            await member.timeout(
                1000 *
                    60 *
                    60 *
                    24,
                'Mass channel modifications detected'
            );

            const everyoneRole =
                guild.roles.everyone;

            guild.channels.cache.forEach(
                async channel => {

                    try {

                        if (
                            channel.type ===
                            ChannelType.GuildText
                        ) {

                            await channel.permissionOverwrites.edit(
                                everyoneRole,
                                {
                                    SendMessages: false
                                }
                            );

                        }

                    } catch (err) {}

                }
            );

            const logChannel =
                guild.channels.cache.find(
                    c =>
                        c.name === 'logs' ||
                        c.name === 'mod-logs'
                );

            if (logChannel) {

                const embed =
                    new EmbedBuilder()
                        .setTitle(
                            '🚨 CHANNEL NUKE DETECTED'
                        )
                        .setColor(
                            'DarkRed'
                        )
                        .setDescription(
                            `${executor.tag} triggered anti-nuke protection.`
                        )
                        .addFields(
                            {
                                name:
                                    'Punishment',
                                value:
                                    '• All roles removed\n' +
                                    '• 24h timeout\n' +
                                    '• Server lockdown enabled'
                            }
                        )
                        .setTimestamp();

                logChannel.send({
                    content:
                        '@everyone',
                    embeds: [embed]
                });

            }

            channelActions[
                executor.id
            ] = [];

        }

    } catch (err) {

        console.log(err);

    }

}

// ===== CHANNEL DELETE =====

client.on(
    'channelDelete',
    async channel => {

        try {

            const logs =
                await channel.guild.fetchAuditLogs(
                    {
                        limit: 1,
                        type:
                            AuditLogEvent.ChannelDelete
                    }
                );

            const entry =
                logs.entries.first();

            if (!entry) return;

            await handleChannelNuke(
                channel.guild,
                entry.executor
            );

        } catch (err) {

            console.log(err);

        }

    }
);

// ===== CHANNEL UPDATE =====

client.on(
    'channelUpdate',
    async (
        oldChannel,
        newChannel
    ) => {

        try {

            const logs =
                await newChannel.guild.fetchAuditLogs(
                    {
                        limit: 1,
                        type:
                            AuditLogEvent.ChannelUpdate
                    }
                );

            const entry =
                logs.entries.first();

            if (!entry) return;

            await handleChannelNuke(
                newChannel.guild,
                entry.executor
            );

        } catch (err) {

            console.log(err);

        }

    }
);

// ===== CHANNEL CREATE =====

client.on(
    'channelCreate',
    async channel => {

        try {

            const logs =
                await channel.guild.fetchAuditLogs(
                    {
                        limit: 1,
                        type:
                            AuditLogEvent.ChannelCreate
                    }
                );

            const entry =
                logs.entries.first();

            if (!entry) return;

            await handleChannelNuke(
                channel.guild,
                entry.executor
            );

        } catch (err) {

            console.log(err);

        }

    }
);

// ================= LOGIN =================

client.login(process.env.TOKEN);