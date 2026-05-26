require('dotenv').config();

process.on('unhandledRejection', console.error);
process.on('uncaughtException', console.error);

const {
    Client,
    GatewayIntentBits,
    PermissionsBitField,
    ChannelType,
    EmbedBuilder,
    ActionRowBuilder,
    ButtonBuilder,
    ButtonStyle,
    AuditLogEvent,
    ApplicationCommandOptionType
} = require('discord.js');

const axios    = require('axios');
const mongoose = require('mongoose');

// ─── client ───────────────────────────────────────────────────────────────────

const client = new Client({
    intents: [
        GatewayIntentBits.Guilds,
        GatewayIntentBits.GuildMembers,
        GatewayIntentBits.GuildMessages,
        GatewayIntentBits.MessageContent,
        GatewayIntentBits.GuildWebhooks,
        GatewayIntentBits.GuildModeration
    ]
});

// ─── db ───────────────────────────────────────────────────────────────────────

(async () => {
    try {
        await mongoose.connect(process.env.MONGO_URI);
        console.log('MongoDB connected.');
    } catch (err) {
        console.error('MongoDB connection failed:', err);
        process.exit(1);
    }
})();

// guild config — anti-raid settings
const guildConfigSchema = new mongoose.Schema({
    guildId:          { type: String, required: true, unique: true, index: true },
    logChannel:       String,
    alertRole:        String,
    whitelistRole:    String,
    whitelistUsers:   [String],
    raidMode:         { type: Boolean, default: false },
    screening:        { type: Boolean, default: true },

    // join / auto-role
    joinRole:         String,
    botRole:          String,
    verifiedRole:     String,
    mutedRole:        String,

    // link filter
    linkFilter:       { type: Boolean, default: false },
    linkWhitelist:    [String],

    // anti-hoisting
    antiHoisting:     { type: Boolean, default: false },
    hoistingName:     { type: String, default: 'Moderated Name' },

    // duplicate / copypaste spam
    antiDuplicates:   { type: Boolean, default: false },
    duplicateLimit:   { type: Number, default: 3 },
    duplicateWindow:  { type: Number, default: 5000 },

    // ghost ping detection
    ghostPingLog:     { type: Boolean, default: false },

    // server owner — per-guild elevated user who can authorize/deauthorize bots
    serverOwner:      String,

    // ── FIX: authorized bot IDs — bots not in this list are kicked on join ───
    authorizedBots:   [String],

    // role connections (up to 5 rules per server)
    roleConnections:  [{ connectionKey: String, roleId: String }]
});
const GuildConfig = mongoose.model('GuildConfig', guildConfigSchema);

// ticket config
const ticketConfigSchema = new mongoose.Schema({
    guildId:          { type: String, required: true, unique: true },
    panelChannelId:   String,
    categoryId:       String,
    logChannelId:     String,
    supportRoleId:    String,
    panelTitle:       { type: String, default: '🎫 Support Tickets' },
    panelDescription: { type: String, default: 'Click the button below to open a support ticket.' },
    panelColor:       { type: String, default: '5865F2' },
    buttonLabel:      { type: String, default: 'Open a Ticket' },
    buttonEmoji:      { type: String, default: '🎫' },
    openMessage:      { type: String, default: 'Welcome! Please describe your issue and a staff member will be with you shortly.' },
    maxOpenPerUser:   { type: Number, default: 1 },
    panelMessageId:   String
});
const TicketConfig = mongoose.model('TicketConfig', ticketConfigSchema);

// individual tickets
const ticketSchema = new mongoose.Schema({
    guildId:   String,
    channelId: String,
    userId:    String,
    ticketNum: Number,
    status:    { type: String, default: 'open' },
    openedAt:  { type: Date,   default: Date.now }
});
const Ticket = mongoose.model('Ticket', ticketSchema);

// ─── constants ────────────────────────────────────────────────────────────────

const OWNER_ID     = '1493407891124654192';
const BOT_VERSION  = '12.1.0';
const GITHUB_OWNER = 'scpenthuasiast-dev';
const GITHUB_REPO  = 'Anti-Raid-Bot';
const FOOTER_TEXT  = 'Developed by Pierce';

// ── GLOBAL BLACKLIST — loaded from .env, comma-separated IDs ─────────────────
const GLOBAL_BLACKLIST = new Set(
    (process.env.GLOBAL_BLACKLIST ?? '')
        .split(',')
        .map(id => id.trim())
        .filter(Boolean)
);

// ── GLOBAL WHITELIST — hardcoded trusted IDs (owner etc.) ────────────────────
const GLOBAL_WHITELIST = new Set([
    '1493407891124654192',
    '1508203353811845130'
]);

// thresholds
const JOIN_LIMIT             = 5;
const JOIN_TIME              = 10000;
const USER_PING_LIMIT        = 5;
const ROLE_PING_LIMIT        = 5;
const EVERYONE_LIMIT         = 2;
const PING_TIME              = 10000;
// ── FIX: tightened from 3/5000 → 2/3000 to catch machine-speed channel nukes
const CHANNEL_NUKE_LIMIT     = 2;
const CHANNEL_NUKE_TIME      = 3000;
const ACCOUNT_AGE_LIMIT      = 1000 * 60 * 60 * 24 * 3;
const MASS_BAN_LIMIT         = 2;
const MASS_BAN_TIME          = 10000;
const MASS_KICK_LIMIT        = 5;
const MASS_KICK_TIME         = 10000;
const MASS_ROLE_DELETE_LIMIT = 3;
const MASS_ROLE_DELETE_TIME  = 10000;
const CATEGORY_SPAM_LIMIT    = 3;
const CATEGORY_SPAM_TIME     = 5000;
const THREAD_SPAM_LIMIT      = 5;
const THREAD_SPAM_TIME       = 10000;
const FORUM_SPAM_LIMIT       = 5;
const FORUM_SPAM_TIME        = 10000;
const EMOJI_NUKE_LIMIT       = 3;
const EMOJI_NUKE_TIME        = 5000;
const STICKER_NUKE_LIMIT     = 3;
const STICKER_NUKE_TIME      = 5000;
const EMBED_SPAM_LIMIT       = 4;
const EMBED_SPAM_TIME        = 10000;
const RAID_SLOWMODE          = 10;

const SUSPICIOUS_USERNAME_PATTERNS = [
    /discord\.gg\//i,
    /nitro\s*gift/i,
    /free\s*nitro/i,
    /free\s*gift/i,
    /\bdiscord.?admin\b/i,
    /\bdiscord.?support\b/i,
    /\bofficial.?staff\b/i,
    /\bmoderator\b/i,
    /hack(?:er|ing|ed)?\b/i,
    /exploit(?:er|ing)?\b/i
];

const INVITE_PATTERN = /discord(?:\.gg|app\.com\/invite|\.com\/invite)\/([a-zA-Z0-9\-]+)/gi;
const URL_PATTERN    = /https?:\/\/[^\s]+/gi;

const DANGEROUS_CHANNEL_PERMS = [
    PermissionsBitField.Flags.ManageChannels,
    PermissionsBitField.Flags.ManageRoles,
    PermissionsBitField.Flags.ManageWebhooks
];

const HOIST_PATTERN = /^[^a-zA-Z0-9\u00C0-\u024F\u4E00-\u9FFF\u3040-\u30FF\uAC00-\uD7AF]/;

// ─── in-memory state ──────────────────────────────────────────────────────────

let joins             = {};
let raidMode          = {};
let mentionTracker    = {};
let channelActions    = {};
let punishedUsers     = {};
let logCooldowns      = {};
let banTracker        = {};
let kickTracker       = {};
let roleDeleteTracker = {};
let categoryTracker   = {};
let threadTracker     = {};
let forumTracker      = {};
let emojiTracker      = {};
let stickerTracker    = {};
let embedTracker      = {};
let duplicateTracker  = {};
let messageCache      = {};

// ─── embed builders ───────────────────────────────────────────────────────────

function alertEmbed(title, description, fields = []) {
    const e = new EmbedBuilder()
        .setTitle(title).setColor(0xE03C3C)
        .setDescription(description)
        .setFooter({ text: FOOTER_TEXT }).setTimestamp();
    if (fields.length) e.addFields(fields);
    return e;
}

function infoEmbed(title, description, color = 0x5865F2, fields = []) {
    const e = new EmbedBuilder()
        .setTitle(title).setColor(color)
        .setDescription(description)
        .setFooter({ text: FOOTER_TEXT }).setTimestamp();
    if (fields.length) e.addFields(fields);
    return e;
}

function warnEmbed(title, description, fields = []) {
    const e = new EmbedBuilder()
        .setTitle(title).setColor(0xFFA500)
        .setDescription(description)
        .setFooter({ text: FOOTER_TEXT }).setTimestamp();
    if (fields.length) e.addFields(fields);
    return e;
}

// ─── core helpers ─────────────────────────────────────────────────────────────

function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

async function getGuildConfig(guildId) {
    return GuildConfig.findOne({ guildId });
}

async function getLogChannel(guild) {
    const config = await getGuildConfig(guild.id);
    if (!config?.logChannel) return null;
    return guild.channels.fetch(config.logChannel).catch(() => null);
}

async function getAlertRole(guild) {
    const config = await getGuildConfig(guild.id);
    if (!config?.alertRole) return null;
    return `<@&${config.alertRole}>`;
}

function isGloballyBlacklisted(userId) {
    return GLOBAL_BLACKLIST.has(userId);
}

async function isWhitelisted(member) {
    if (!member) return false;
    if (GLOBAL_WHITELIST.has(member.id)) return true;
    const config = await getGuildConfig(member.guild.id);
    if (!config) return false;
    if (config.whitelistRole && member.roles.cache.has(config.whitelistRole)) return true;
    if (config.whitelistUsers?.includes(member.id)) return true;
    return false;
}

async function hasStaffAccess(member) {
    if (!member) return false;
    if (GLOBAL_WHITELIST.has(member.id)) return true;
    if (!member.permissions?.has(PermissionsBitField.Flags.Administrator)) return false;
    const config = await getGuildConfig(member.guild.id);
    if (!config) return false;
    if (config.whitelistRole && member.roles.cache.has(config.whitelistRole)) return true;
    if (config.whitelistUsers?.includes(member.id)) return true;
    return false;
}

// isServerOwner: per-guild elevated role — can authorize/deauthorize bots for their server only.
// Global whitelist always passes. Otherwise checks the serverOwner field in the guild config.
async function isServerOwner(userId, guildId) {
    if (GLOBAL_WHITELIST.has(userId)) return true;
    const config = await getGuildConfig(guildId);
    return config?.serverOwner === userId;
}

async function fetchAuditEntry(guild, type, targetId = null, retries = 3, delayMs = 600) {
    for (let attempt = 0; attempt < retries; attempt++) {
        if (attempt > 0) await sleep(delayMs * attempt);
        try {
            const logs  = await guild.fetchAuditLogs({ limit: 5, type });
            const entry = targetId
                ? logs.entries.find(e => e.target?.id === targetId)
                : logs.entries.first();
            if (entry) return entry;
        } catch (err) {
            console.warn(`[AuditLog] Attempt ${attempt + 1} failed (type ${type}):`, err.message);
        }
    }
    return null;
}

async function sendLog(guild, embed, cooldownKey = null) {
    const logChannel = await getLogChannel(guild);
    if (!logChannel) return;

    const key = cooldownKey ?? embed.data?.title ?? 'generic';
    if (!logCooldowns[guild.id]) logCooldowns[guild.id] = {};
    if (logCooldowns[guild.id][key]) return;
    logCooldowns[guild.id][key] = true;
    setTimeout(() => { delete logCooldowns[guild.id]?.[key]; }, 10000);

    const alertRole = await getAlertRole(guild);
    try {
        await logChannel.send({ content: alertRole ?? undefined, embeds: [embed] });
    } catch (err) {
        console.error(`[LOG] Failed in guild ${guild.id}:`, err.message);
    }
}

async function lockServer(guild) {
    const everyone = guild.roles.everyone;
    for (const channel of guild.channels.cache.values()) {
        try {
            if (channel.type === ChannelType.GuildText) {
                await channel.permissionOverwrites.edit(everyone, { SendMessages: false });
                await channel.setRateLimitPerUser(RAID_SLOWMODE);
            } else if (channel.type === ChannelType.GuildForum) {
                await channel.permissionOverwrites.edit(everyone, { SendMessages: false });
            }
        } catch {}
    }
    await GuildConfig.findOneAndUpdate(
        { guildId: guild.id },
        { $set: { guildId: guild.id, raidMode: true } },
        { upsert: true }
    ).catch(() => {});
}

async function unlockServer(guild) {
    const everyone = guild.roles.everyone;
    for (const channel of guild.channels.cache.values()) {
        try {
            if (channel.type === ChannelType.GuildText) {
                await channel.permissionOverwrites.edit(everyone, { SendMessages: null });
                await channel.setRateLimitPerUser(0);
            } else if (channel.type === ChannelType.GuildForum) {
                await channel.permissionOverwrites.edit(everyone, { SendMessages: null });
            }
        } catch {}
    }
    await GuildConfig.findOneAndUpdate(
        { guildId: guild.id },
        { $set: { guildId: guild.id, raidMode: false } },
        { upsert: true }
    ).catch(() => {});
}

async function stripRoles(member) {
    for (const role of member.roles.cache.values()) {
        if (role.id !== member.guild.id) {
            try { await member.roles.remove(role); } catch {}
        }
    }
}

function trackAction(tracker, guildId, userId, windowMs) {
    if (!tracker[guildId]) tracker[guildId] = {};
    if (!tracker[guildId][userId]) tracker[guildId][userId] = [];
    tracker[guildId][userId].push(Date.now());
    tracker[guildId][userId] = tracker[guildId][userId].filter(t => Date.now() - t < windowMs);
    return tracker[guildId][userId].length;
}

// ── FIX: punishExecutor now bans the executor (including bots) ────────────────
async function punishExecutor(guild, executorId, embed) {
    try {
        const member = await guild.members.fetch(executorId).catch(() => null);
        if (!member) return;
        if (await isWhitelisted(member)) return;
        if (!punishedUsers[guild.id]) punishedUsers[guild.id] = {};
        if (punishedUsers[guild.id][executorId]) return;
        punishedUsers[guild.id][executorId] = true;
        setTimeout(() => { delete punishedUsers[guild.id]?.[executorId]; }, 30000);

        // strip roles first (fast), then ban — works for both humans and bots
        await stripRoles(member);
        try {
            await guild.members.ban(executorId, { reason: 'Anti-raid: automated punishment' });
        } catch (banErr) {
            console.warn(`[punishExecutor] Ban failed for ${executorId}:`, banErr.message);
        }

        const titleKey = embed.data?.title ?? 'generic';
        await sendLog(guild, embed, `${titleKey}:${executorId}`);
    } catch {}
}

async function dmAndKick(member, kickReason, dmBody) {
    try {
        await member.user.send({
            embeds: [warnEmbed('⚠️ You were kicked', `You were kicked from **${member.guild.name}**.\n\n**Reason:** ${dmBody}\n\nContact the server admins if you think this is a mistake.`)]
        });
    } catch {}
    await member.kick(kickReason);
}

async function globalBan(userId, reason) {
    const results = [];
    for (const guild of client.guilds.cache.values()) {
        try {
            await guild.members.ban(userId, { reason });
            results.push({ guild: guild.name, success: true });
        } catch (err) {
            results.push({ guild: guild.name, success: false, error: err.message });
        }
    }
    return results;
}

// ─── ticket helpers ───────────────────────────────────────────────────────────

async function getTicketConfig(guildId) {
    return TicketConfig.findOne({ guildId });
}

async function sendTicketPanel(guild, config, channelOverride = null) {
    const targetId = channelOverride ?? config.panelChannelId;
    if (!targetId) return null;
    const channel = await guild.channels.fetch(targetId).catch(() => null);
    if (!channel) return null;

    const colorHex = parseInt(config.panelColor?.replace('#', '') ?? '5865F2', 16);
    const embed = new EmbedBuilder()
        .setTitle(config.panelTitle)
        .setDescription(config.panelDescription)
        .setColor(colorHex)
        .setFooter({ text: `${guild.name} • Support | ${FOOTER_TEXT}` })
        .setTimestamp();

    const row = new ActionRowBuilder().addComponents(
        new ButtonBuilder()
            .setCustomId('ticket_open')
            .setLabel(config.buttonLabel)
            .setEmoji(config.buttonEmoji)
            .setStyle(ButtonStyle.Primary)
    );

    if (config.panelMessageId) {
        try {
            const existing = await channel.messages.fetch(config.panelMessageId);
            await existing.edit({ embeds: [embed], components: [row] });
            return existing;
        } catch {}
    }

    const msg = await channel.send({ embeds: [embed], components: [row] });
    await TicketConfig.findOneAndUpdate(
        { guildId: guild.id },
        { $set: { panelMessageId: msg.id } },
        { upsert: true }
    );
    return msg;
}

async function openTicket(guild, user, ticketCfg) {
    const openCount = await Ticket.countDocuments({ guildId: guild.id, userId: user.id, status: 'open' });
    if (openCount >= ticketCfg.maxOpenPerUser) {
        return { error: `You already have ${openCount} open ticket(s). Please wait for it to be resolved.` };
    }

    const total     = await Ticket.countDocuments({ guildId: guild.id });
    const ticketNum = total + 1;

    const category = ticketCfg.categoryId
        ? await guild.channels.fetch(ticketCfg.categoryId).catch(() => null)
        : null;

    const overwrites = [
        { id: guild.id,  deny:  [PermissionsBitField.Flags.ViewChannel] },
        { id: user.id,   allow: [PermissionsBitField.Flags.ViewChannel, PermissionsBitField.Flags.SendMessages, PermissionsBitField.Flags.ReadMessageHistory] }
    ];
    if (ticketCfg.supportRoleId) {
        overwrites.push({ id: ticketCfg.supportRoleId, allow: [PermissionsBitField.Flags.ViewChannel, PermissionsBitField.Flags.SendMessages, PermissionsBitField.Flags.ReadMessageHistory, PermissionsBitField.Flags.ManageMessages] });
    }

    const channel = await guild.channels.create({
        name:                 `ticket-${ticketNum}`,
        type:                 ChannelType.GuildText,
        parent:               category?.id ?? null,
        permissionOverwrites: overwrites,
        topic:                `Ticket #${ticketNum} opened by ${user.tag}`
    });

    await Ticket.create({ guildId: guild.id, channelId: channel.id, userId: user.id, ticketNum });

    const embed = new EmbedBuilder()
        .setTitle(`🎫 Ticket #${ticketNum}`)
        .setDescription(ticketCfg.openMessage)
        .setColor(0x5865F2)
        .addFields(
            { name: 'Opened By', value: `<@${user.id}>`, inline: true },
            { name: 'Ticket #',  value: `${ticketNum}`,  inline: true }
        )
        .setFooter({ text: FOOTER_TEXT })
        .setTimestamp();

    const row = new ActionRowBuilder().addComponents(
        new ButtonBuilder().setCustomId('ticket_close').setLabel('Close Ticket').setEmoji('🔒').setStyle(ButtonStyle.Danger),
        new ButtonBuilder().setCustomId('ticket_claim').setLabel('Claim').setEmoji('✋').setStyle(ButtonStyle.Secondary)
    );

    await channel.send({
        content: `<@${user.id}>${ticketCfg.supportRoleId ? ` <@&${ticketCfg.supportRoleId}>` : ''}`,
        embeds: [embed],
        components: [row]
    });

    return { channel, ticketNum };
}

async function closeTicket(channel, guild, closedBy) {
    const ticket = await Ticket.findOne({ guildId: guild.id, channelId: channel.id, status: 'open' });
    if (!ticket) return false;

    ticket.status = 'closed';
    await ticket.save();

    try { await channel.permissionOverwrites.edit(ticket.userId, { SendMessages: false }); } catch {}

    const embed = new EmbedBuilder()
        .setTitle('🔒 Ticket Closed')
        .setDescription(`Closed by <@${closedBy.id}>.`)
        .setColor(0xE03C3C)
        .setFooter({ text: FOOTER_TEXT })
        .setTimestamp();

    const row = new ActionRowBuilder().addComponents(
        new ButtonBuilder().setCustomId('ticket_delete').setLabel('Delete Channel').setEmoji('🗑️').setStyle(ButtonStyle.Danger),
        new ButtonBuilder().setCustomId('ticket_reopen').setLabel('Re-open').setEmoji('🔓').setStyle(ButtonStyle.Secondary)
    );

    await channel.send({ embeds: [embed], components: [row] });

    const ticketCfg = await getTicketConfig(guild.id);
    if (ticketCfg?.logChannelId) {
        const logCh = await guild.channels.fetch(ticketCfg.logChannelId).catch(() => null);
        if (logCh) {
            await logCh.send({
                embeds: [new EmbedBuilder()
                    .setTitle(`Ticket #${ticket.ticketNum} Closed`)
                    .setColor(0xFFA500)
                    .addFields(
                        { name: 'Opened By', value: `<@${ticket.userId}>`, inline: true },
                        { name: 'Closed By', value: `<@${closedBy.id}>`,   inline: true },
                        { name: 'Channel',   value: channel.name,          inline: true }
                    )
                    .setFooter({ text: FOOTER_TEXT })
                    .setTimestamp()
                ]
            });
        }
    }

    return true;
}

// ─── slash command definitions ────────────────────────────────────────────────

const COMMANDS = [
    // public
    { name: 'botinfo',   description: 'View bot info' },
    { name: 'changelog', description: 'View the latest updates from GitHub' },

    // staff
    {
        name: 'whitelistuser',
        description: 'Add a user to this server\'s whitelist',
        options: [{ name: 'user', description: 'User', type: ApplicationCommandOptionType.User, required: true }]
    },
    {
        name: 'unwhitelistuser',
        description: 'Remove a user from this server\'s whitelist',
        options: [{ name: 'user', description: 'User', type: ApplicationCommandOptionType.User, required: true }]
    },
    { name: 'whitelistlist',  description: 'View whitelisted users and role' },
    { name: 'lockdown',       description: 'Lock all channels' },
    { name: 'unlockdown',     description: 'Unlock all channels' },
    { name: 'raidmode',       description: 'Enable raid mode and lock the server' },
    { name: 'unraidmode',     description: 'Disable raid mode and unlock the server' },
    {
        name: 'unban',
        description: 'Unban a user by ID',
        options: [
            { name: 'userid', description: 'User ID to unban', type: ApplicationCommandOptionType.String, required: true },
            { name: 'reason', description: 'Reason',           type: ApplicationCommandOptionType.String, required: false }
        ]
    },
    {
        name: 'globalban',
        description: 'Ban a user from ALL servers this bot is in',
        options: [
            { name: 'userid', description: 'User ID to globally ban', type: ApplicationCommandOptionType.String, required: true },
            { name: 'reason', description: 'Reason',                  type: ApplicationCommandOptionType.String, required: false }
        ]
    },
    {
        name: 'setlogchannel',
        description: 'Set the channel for bot alerts and logs',
        options: [{ name: 'channel', description: 'Log channel', type: ApplicationCommandOptionType.Channel, required: true }]
    },
    {
        name: 'setalertrole',
        description: 'Set the role pinged on alerts',
        options: [{ name: 'role', description: 'Alert role', type: ApplicationCommandOptionType.Role, required: true }]
    },
    {
        name: 'setwhitelistrole',
        description: 'Set the role that bypasses anti-raid checks AND grants staff command access',
        options: [{ name: 'role', description: 'Whitelist role', type: ApplicationCommandOptionType.Role, required: true }]
    },

    // server customization
    {
        name: 'setjoinrole',
        description: 'Set a role automatically given to every user who joins',
        options: [{ name: 'role', description: 'Join role (use "none" to disable)', type: ApplicationCommandOptionType.Role, required: false }]
    },
    {
        name: 'setbotrole',
        description: 'Set a role automatically given to bots when they join (if authorized)',
        options: [{ name: 'role', description: 'Bot role', type: ApplicationCommandOptionType.Role, required: false }]
    },
    {
        name: 'setmutedrole',
        description: 'Set the role used by the bot to mute members',
        options: [{ name: 'role', description: 'Muted role', type: ApplicationCommandOptionType.Role, required: true }]
    },
    {
        name: 'mute',
        description: 'Mute a member by assigning the muted role',
        options: [
            { name: 'user',   description: 'User to mute',    type: ApplicationCommandOptionType.User,    required: true },
            { name: 'reason', description: 'Reason for mute', type: ApplicationCommandOptionType.String,  required: false }
        ]
    },
    {
        name: 'unmute',
        description: 'Unmute a member by removing the muted role',
        options: [{ name: 'user', description: 'User to unmute', type: ApplicationCommandOptionType.User, required: true }]
    },
    {
        name: 'setlinkfilter',
        description: 'Enable or disable the Discord invite / link filter',
        options: [
            { name: 'enabled',   description: 'Enable filtering',                                type: ApplicationCommandOptionType.Boolean, required: true },
            { name: 'whitelist', description: 'Comma-separated allowed domains or invite codes', type: ApplicationCommandOptionType.String,  required: false }
        ]
    },
    {
        name: 'setantihoisting',
        description: 'Enable or disable anti-hoisting',
        options: [
            { name: 'enabled',  description: 'Enable anti-hoisting',                            type: ApplicationCommandOptionType.Boolean, required: true },
            { name: 'nickname', description: 'Name to assign (default: "Moderated Name")',       type: ApplicationCommandOptionType.String,  required: false }
        ]
    },
    {
        name: 'setantiduplicates',
        description: 'Enable or disable duplicate/copy-paste spam detection',
        options: [
            { name: 'enabled', description: 'Enable detection',                              type: ApplicationCommandOptionType.Boolean, required: true },
            { name: 'limit',   description: 'Same message count before action (default 3)',  type: ApplicationCommandOptionType.Integer, required: false },
            { name: 'window',  description: 'Time window in seconds (default 5)',             type: ApplicationCommandOptionType.Integer, required: false }
        ]
    },
    {
        name: 'setghostpinglog',
        description: 'Enable or disable ghost ping detection and logging',
        options: [{ name: 'enabled', description: 'Enable ghost ping logging', type: ApplicationCommandOptionType.Boolean, required: true }]
    },
    {
        name: 'setscreening',
        description: 'Toggle join screening (no-pfp / new account / suspicious username kicks)',
        options: [{ name: 'enabled', description: 'Enable screening', type: ApplicationCommandOptionType.Boolean, required: true }]
    },

    // ── NEW: bot authorization ────────────────────────────────────────────────
    // setserverowner / removeserverowner — global whitelist only, sets a per-guild
    // "server owner" user who is the only one (besides global whitelist) allowed
    // to authorize and de-authorize bots for that specific server.
    {
        name: 'setserverowner',
        description: 'Assign a server owner who can authorize/de-authorize bots for this server (global owners only)',
        options: [
            { name: 'user', description: 'The user to designate as server owner', type: ApplicationCommandOptionType.User, required: true }
        ]
    },
    {
        name: 'removeserverowner',
        description: 'Remove the current server owner designation for this server (global owners only)'
    },
    { name: 'serverowner', description: 'Show who the current server owner is for this server' },
    {
        name: 'authorizebot',
        description: 'Pre-authorize a bot ID to join this server without being kicked (server owner only)',
        options: [
            { name: 'botid',  description: 'The bot\'s Discord user ID',         type: ApplicationCommandOptionType.String,  required: true },
            { name: 'reason', description: 'Why this bot is being authorized',   type: ApplicationCommandOptionType.String,  required: false }
        ]
    },
    {
        name: 'deauthorizebot',
        description: 'Remove a bot from the authorized list (server owner only)',
        options: [
            { name: 'botid', description: 'The bot\'s Discord user ID to remove', type: ApplicationCommandOptionType.String, required: true }
        ]
    },
    { name: 'authorizedbots', description: 'List all pre-authorized bots for this server' },

    // role connections
    {
        name: 'roleconnectionadd',
        description: 'Link a Discord role connection type to a server role',
        options: [
            { name: 'connection_key', description: 'The role connection metadata key (e.g. twitch_subscriber)', type: ApplicationCommandOptionType.String, required: true },
            { name: 'role',           description: 'Role to assign when the connection is verified',             type: ApplicationCommandOptionType.Role,   required: true }
        ]
    },
    {
        name: 'roleconnectionremove',
        description: 'Remove a role connection rule',
        options: [{ name: 'connection_key', description: 'The connection key to remove', type: ApplicationCommandOptionType.String, required: true }]
    },
    { name: 'roleconnectionlist', description: 'List all role connection rules for this server' },
    { name: 'serverconfig',       description: 'View all configuration settings for this server' },

    // ticket system
    {
        name: 'ticketsetup',
        description: 'Configure the ticket system',
        options: [
            { name: 'panel_channel', description: 'Channel for the ticket panel',             type: ApplicationCommandOptionType.Channel, required: true },
            { name: 'category',      description: 'Category that ticket channels open under', type: ApplicationCommandOptionType.Channel, required: true },
            { name: 'log_channel',   description: 'Channel for ticket logs',                  type: ApplicationCommandOptionType.Channel, required: true },
            { name: 'support_role',  description: 'Role that can manage tickets',             type: ApplicationCommandOptionType.Role,    required: true },
            { name: 'panel_title',   description: 'Panel embed title',                        type: ApplicationCommandOptionType.String,  required: false },
            { name: 'panel_desc',    description: 'Panel embed description',                  type: ApplicationCommandOptionType.String,  required: false },
            { name: 'panel_color',   description: 'Panel embed color (e.g. #FF0000)',         type: ApplicationCommandOptionType.String,  required: false },
            { name: 'button_label',  description: 'Open ticket button label',                 type: ApplicationCommandOptionType.String,  required: false },
            { name: 'button_emoji',  description: 'Open ticket button emoji',                 type: ApplicationCommandOptionType.String,  required: false },
            { name: 'open_message',  description: 'Message sent inside a new ticket',         type: ApplicationCommandOptionType.String,  required: false },
            { name: 'max_per_user',  description: 'Max open tickets per user (default 1)',    type: ApplicationCommandOptionType.Integer, required: false }
        ]
    },
    { name: 'ticketpanel',  description: 'Re-post or refresh the ticket panel' },
    { name: 'ticketclose',  description: 'Close the ticket in the current channel' },
    {
        name: 'ticketadd',
        description: 'Add a user to the current ticket',
        options: [{ name: 'user', description: 'User to add', type: ApplicationCommandOptionType.User, required: true }]
    },
    {
        name: 'ticketremove',
        description: 'Remove a user from the current ticket',
        options: [{ name: 'user', description: 'User to remove', type: ApplicationCommandOptionType.User, required: true }]
    }
];

// ─── ready ────────────────────────────────────────────────────────────────────

client.once('ready', async () => {
    console.log(`${client.user.tag} is online (v${BOT_VERSION}).`);
    console.log(`Global blacklist loaded: ${GLOBAL_BLACKLIST.size} IDs`);

    try {
        const configs = await GuildConfig.find({ raidMode: true });
        for (const c of configs) {
            raidMode[c.guildId] = true;
            console.log(`[STARTUP] Raid mode restored for guild ${c.guildId}`);
        }
    } catch (err) {
        console.error('[STARTUP] Failed to restore raid mode:', err.message);
    }

    for (const guild of client.guilds.cache.values()) {
        try {
            await guild.commands.set(COMMANDS);
            console.log(`Commands registered in ${guild.name}`);
        } catch (err) {
            console.error(`Command registration failed in ${guild.name}:`, err.message);
        }
    }
});

// ─── interactions ─────────────────────────────────────────────────────────────

client.on('interactionCreate', async interaction => {

    // ── button handler ────────────────────────────────────────────────────────
    if (interaction.isButton()) {
        const { customId, guild, member, channel } = interaction;

        if (customId === 'ticket_open') {
            const ticketCfg = await getTicketConfig(guild.id);
            if (!ticketCfg) return interaction.reply({ content: '❌ Ticket system not configured. Ask an admin to run `/ticketsetup`.', ephemeral: true });
            await interaction.deferReply({ ephemeral: true });
            const result = await openTicket(guild, interaction.user, ticketCfg);
            if (result.error) return interaction.editReply({ content: `❌ ${result.error}` });
            return interaction.editReply({ content: `✅ Ticket opened: ${result.channel}` });
        }

        if (customId === 'ticket_close') {
            const ticket  = await Ticket.findOne({ guildId: guild.id, channelId: channel.id });
            const isStaff = await hasStaffAccess(member);
            const isOwner = ticket?.userId === interaction.user.id;
            if (!isStaff && !isOwner) return interaction.reply({ content: '❌ Only staff or the ticket owner can close this ticket.', ephemeral: true });
            await interaction.deferUpdate();
            await closeTicket(channel, guild, interaction.user);
            return;
        }

        if (customId === 'ticket_claim') {
            if (!(await hasStaffAccess(member))) return interaction.reply({ content: '❌ Only staff can claim tickets.', ephemeral: true });
            return interaction.reply({ content: `✋ Ticket claimed by <@${interaction.user.id}>.` });
        }

        if (customId === 'ticket_delete') {
            if (!(await hasStaffAccess(member))) return interaction.reply({ content: '❌ Only staff can delete ticket channels.', ephemeral: true });
            await interaction.reply({ content: '🗑️ Deleting channel in 3 seconds...' });
            setTimeout(() => channel.delete().catch(() => {}), 3000);
            return;
        }

        if (customId === 'ticket_reopen') {
            if (!(await hasStaffAccess(member))) return interaction.reply({ content: '❌ Only staff can re-open tickets.', ephemeral: true });
            const ticket = await Ticket.findOne({ guildId: guild.id, channelId: channel.id });
            if (!ticket) return interaction.reply({ content: '❌ No ticket record found.', ephemeral: true });
            ticket.status = 'open';
            await ticket.save();
            try { await channel.permissionOverwrites.edit(ticket.userId, { SendMessages: true }); } catch {}
            return interaction.reply({
                embeds: [infoEmbed('🔓 Ticket Re-opened', `Re-opened by <@${interaction.user.id}>.`, 0x57F287)]
            });
        }

        return;
    }

    if (!interaction.isChatInputCommand()) return;

    const { commandName: command, guild, member, user } = interaction;

    // ── public commands ───────────────────────────────────────────────────────

    if (command === 'botinfo') {
        return interaction.reply({
            embeds: [new EmbedBuilder()
                .setTitle('🤖 Anti-Raid Bot Info')
                .setColor(0x5865F2)
                .setThumbnail(client.user.displayAvatarURL())
                .addFields(
                    { name: '📦 Version',   value: BOT_VERSION,                                                            inline: true },
                    { name: '🌐 Servers',   value: `${client.guilds.cache.size}`,                                         inline: true },
                    { name: '⏱️ Uptime',    value: `<t:${Math.floor((Date.now() - client.uptime) / 1000)}:R>`,            inline: true },
                    { name: '🔒 Raid Mode', value: raidMode[guild.id] ? '🔴 Active' : '🟢 Inactive',                     inline: true },
                    { name: '🐙 GitHub',    value: `[View Repository](https://github.com/${GITHUB_OWNER}/${GITHUB_REPO})`, inline: false }
                )
                .setFooter({ text: FOOTER_TEXT })
                .setTimestamp()
            ],
            ephemeral: true
        });
    }

    if (command === 'changelog') {
        try {
            const res     = await axios.get(`https://api.github.com/repos/${GITHUB_OWNER}/${GITHUB_REPO}/releases/latest`);
            const release = res.data;
            return interaction.reply({
                embeds: [new EmbedBuilder()
                    .setTitle(`📋 Changelog — ${release.tag_name}`)
                    .setColor(0x57F287)
                    .setDescription(release.body?.slice(0, 4000) || 'No notes available.')
                    .setURL(release.html_url)
                    .setFooter({ text: FOOTER_TEXT })
                    .setTimestamp()
                ],
                ephemeral: true
            });
        } catch {
            return interaction.reply({ embeds: [infoEmbed('❌ Error', 'Could not fetch changelog from GitHub.', 0xE03C3C)], ephemeral: true });
        }
    }

    // ── staff gate ────────────────────────────────────────────────────────────
    if (!(await hasStaffAccess(member))) {
        return interaction.reply({
            embeds: [infoEmbed('❌ Access Denied',
                'You need **Administrator** permission **and** be on this server\'s whitelist to use this command.',
                0xE03C3C
            )],
            ephemeral: true
        });
    }

    // ── anti-raid config ──────────────────────────────────────────────────────

    if (command === 'setlogchannel') {
        const channel = interaction.options.getChannel('channel');
        await GuildConfig.findOneAndUpdate({ guildId: guild.id }, { $set: { guildId: guild.id, logChannel: channel.id } }, { upsert: true });
        await sendLog(guild, infoEmbed('📋 Log Channel Updated', `Set to ${channel}.`, 0x57F287, [{ name: 'By', value: `${user.tag}`, inline: true }]), `setlogchannel:${user.id}`);
        return interaction.reply({ embeds: [infoEmbed('✅ Log Channel Set', `Logs → ${channel}`, 0x57F287)], ephemeral: true });
    }

    if (command === 'setalertrole') {
        const role = interaction.options.getRole('role');
        await GuildConfig.findOneAndUpdate({ guildId: guild.id }, { $set: { guildId: guild.id, alertRole: role.id } }, { upsert: true });
        await sendLog(guild, infoEmbed('🔔 Alert Role Updated', `Set to ${role}.`, 0x57F287, [{ name: 'By', value: `${user.tag}`, inline: true }]), `setalertrole:${user.id}`);
        return interaction.reply({ embeds: [infoEmbed('✅ Alert Role Set', `${role} will be pinged on alerts.`, 0x57F287)], ephemeral: true });
    }

    if (command === 'setwhitelistrole') {
        const role = interaction.options.getRole('role');
        await GuildConfig.findOneAndUpdate({ guildId: guild.id }, { $set: { guildId: guild.id, whitelistRole: role.id } }, { upsert: true });
        await sendLog(guild, infoEmbed('🛡️ Whitelist Role Updated', `Set to ${role}.`, 0x57F287, [{ name: 'By', value: `${user.tag}`, inline: true }]), `setwhitelistrole:${user.id}`);
        return interaction.reply({ embeds: [infoEmbed('✅ Whitelist Role Set', `${role} members now bypass checks and have staff access.`, 0x57F287)], ephemeral: true });
    }

    if (command === 'whitelistuser') {
        const target = interaction.options.getUser('user');
        await GuildConfig.findOneAndUpdate({ guildId: guild.id }, { $set: { guildId: guild.id }, $addToSet: { whitelistUsers: target.id } }, { upsert: true });
        await sendLog(guild, infoEmbed('🛡️ User Whitelisted', `${target.tag} added.`, 0x57F287, [{ name: 'By', value: `${user.tag}`, inline: true }]), `whitelist-add:${target.id}`);
        return interaction.reply({ embeds: [infoEmbed('✅ Whitelisted', `${target.tag} can now bypass anti-raid checks and use staff commands.`, 0x57F287)], ephemeral: true });
    }

    if (command === 'unwhitelistuser') {
        const target = interaction.options.getUser('user');
        await GuildConfig.findOneAndUpdate({ guildId: guild.id }, { $pull: { whitelistUsers: target.id } });
        await sendLog(guild, infoEmbed('🛡️ User Removed from Whitelist', `${target.tag} removed.`, 0xFFA500, [{ name: 'By', value: `${user.tag}`, inline: true }]), `whitelist-remove:${target.id}`);
        return interaction.reply({ embeds: [infoEmbed('✅ Removed', `${target.tag} removed from whitelist.`, 0xFFA500)], ephemeral: true });
    }

    if (command === 'whitelistlist') {
        const config   = await getGuildConfig(guild.id);
        const userList = config?.whitelistUsers?.length ? config.whitelistUsers.map(id => `<@${id}>`).join('\n') : 'None';
        const roleText = config?.whitelistRole ? `<@&${config.whitelistRole}>` : 'Not set';
        return interaction.reply({
            embeds: [infoEmbed('🛡️ Whitelist', '', 0x5865F2, [
                { name: 'Whitelist Role',    value: roleText,  inline: false },
                { name: 'Whitelisted Users', value: userList,  inline: false }
            ])],
            ephemeral: true
        });
    }

    if (command === 'lockdown') {
        await lockServer(guild);
        await sendLog(guild, infoEmbed('🔒 Server Locked Down', 'Manually locked by an admin.', 0xFFA500, [{ name: 'By', value: `${user.tag}`, inline: true }]), `lockdown:${user.id}`);
        return interaction.reply({ embeds: [infoEmbed('🔒 Locked', 'All channels locked.', 0xFFA500)], ephemeral: true });
    }

    if (command === 'unlockdown') {
        await unlockServer(guild);
        await sendLog(guild, infoEmbed('🔓 Server Unlocked', 'Manually unlocked by an admin.', 0x57F287, [{ name: 'By', value: `${user.tag}`, inline: true }]), `unlockdown:${user.id}`);
        return interaction.reply({ embeds: [infoEmbed('🔓 Unlocked', 'All channels unlocked.', 0x57F287)], ephemeral: true });
    }

    if (command === 'raidmode') {
        raidMode[guild.id] = true;
        await lockServer(guild);
        await sendLog(guild, alertEmbed('🚨 Raid Mode Enabled', 'Manually enabled.', [{ name: 'By', value: `${user.tag}`, inline: true }]), `raidmode:${user.id}`);
        return interaction.reply({ embeds: [alertEmbed('🚨 Raid Mode Enabled', 'Server locked. Use `/unraidmode` to unlock.')], ephemeral: true });
    }

    if (command === 'unraidmode') {
        raidMode[guild.id] = false;
        await unlockServer(guild);
        await sendLog(guild, infoEmbed('✅ Raid Mode Disabled', 'Manually disabled.', 0x57F287, [{ name: 'By', value: `${user.tag}`, inline: true }]), `unraidmode:${user.id}`);
        return interaction.reply({ embeds: [infoEmbed('✅ Raid Mode Disabled', 'Server unlocked.', 0x57F287)], ephemeral: true });
    }

    if (command === 'unban') {
        const userId = interaction.options.getString('userid').trim();
        const reason = interaction.options.getString('reason') ?? 'No reason provided';
        if (!/^\d{17,20}$/.test(userId)) {
            return interaction.reply({ embeds: [infoEmbed('❌ Invalid ID', 'Provide a valid 17-20 digit Discord user ID.', 0xE03C3C)], ephemeral: true });
        }
        try {
            const ban = await guild.bans.fetch(userId).catch(() => null);
            if (!ban) return interaction.reply({ embeds: [infoEmbed('❌ Not Banned', `No ban found for \`${userId}\`.`, 0xFFA500)], ephemeral: true });
            await guild.members.unban(userId, `${reason} — by ${user.tag}`);
            await sendLog(guild, infoEmbed('✅ User Unbanned', `<@${userId}> was unbanned.`, 0x57F287, [
                { name: 'User ID',     value: userId,        inline: true },
                { name: 'Unbanned By', value: `${user.tag}`, inline: true },
                { name: 'Reason',      value: reason,        inline: false }
            ]), `unban:${userId}`);
            return interaction.reply({ embeds: [infoEmbed('✅ Unbanned', `<@${userId}> has been unbanned.`, 0x57F287)], ephemeral: true });
        } catch (err) {
            return interaction.reply({ embeds: [infoEmbed('❌ Failed', err.message, 0xE03C3C)], ephemeral: true });
        }
    }

    if (command === 'globalban') {
        if (!GLOBAL_WHITELIST.has(user.id)) {
            return interaction.reply({ embeds: [infoEmbed('❌ Owner Only', 'Only the bot owner can issue global bans.', 0xE03C3C)], ephemeral: true });
        }
        const userId = interaction.options.getString('userid').trim();
        const reason = interaction.options.getString('reason') ?? 'Global ban issued by bot owner';
        if (!/^\d{17,20}$/.test(userId)) {
            return interaction.reply({ embeds: [infoEmbed('❌ Invalid ID', 'Provide a valid 17-20 digit Discord user ID.', 0xE03C3C)], ephemeral: true });
        }
        await interaction.deferReply({ ephemeral: true });
        const results = await globalBan(userId, reason);
        const success = results.filter(r => r.success).length;
        const failed  = results.filter(r => !r.success).length;
        return interaction.editReply({
            embeds: [alertEmbed('🔨 Global Ban Executed', `User \`${userId}\` was banned from **${success}** server(s). Failed in **${failed}**.`, [
                { name: 'Reason',    value: reason,        inline: false },
                { name: 'Issued By', value: `${user.tag}`, inline: true },
                { name: 'Success',   value: `${success}`,  inline: true },
                { name: 'Failed',    value: `${failed}`,   inline: true }
            ])]
        });
    }

    // ── server owner management (global whitelist only) ───────────────────────

    if (command === 'setserverowner') {
        if (!GLOBAL_WHITELIST.has(user.id)) {
            return interaction.reply({ embeds: [infoEmbed('❌ Global Owner Only', 'Only global bot owners can designate a server owner.', 0xE03C3C)], ephemeral: true });
        }
        const target = interaction.options.getUser('user');
        await GuildConfig.findOneAndUpdate(
            { guildId: guild.id },
            { $set: { guildId: guild.id, serverOwner: target.id } },
            { upsert: true }
        );
        await sendLog(guild, infoEmbed('👑 Server Owner Set', `${target.tag} is now the server owner for this server.`, 0x57F287, [
            { name: 'User',   value: `${target.tag} (${target.id})`, inline: true },
            { name: 'Set By', value: `${user.tag}`,                  inline: true },
            { name: 'Perms',  value: 'Can authorize and de-authorize bots for this server only', inline: false }
        ]), `set-serverowner:${target.id}`);
        return interaction.reply({
            embeds: [infoEmbed('✅ Server Owner Set', `${target.tag} can now authorize and de-authorize bots for **${guild.name}**.\n\nThis permission applies to this server only.`, 0x57F287)],
            ephemeral: true
        });
    }

    if (command === 'removeserverowner') {
        if (!GLOBAL_WHITELIST.has(user.id)) {
            return interaction.reply({ embeds: [infoEmbed('❌ Global Owner Only', 'Only global bot owners can remove a server owner.', 0xE03C3C)], ephemeral: true });
        }
        const config = await getGuildConfig(guild.id);
        if (!config?.serverOwner) {
            return interaction.reply({ embeds: [infoEmbed('❌ No Server Owner', 'This server has no server owner set.', 0xFFA500)], ephemeral: true });
        }
        const prevId = config.serverOwner;
        await GuildConfig.findOneAndUpdate({ guildId: guild.id }, { $unset: { serverOwner: '' } });
        await sendLog(guild, infoEmbed('👑 Server Owner Removed', `<@${prevId}> is no longer the server owner.`, 0xFFA500, [
            { name: 'Removed By', value: `${user.tag}`, inline: true }
        ]), `remove-serverowner:${prevId}`);
        return interaction.reply({ embeds: [infoEmbed('✅ Server Owner Removed', `<@${prevId}> has been removed as server owner.`, 0xFFA500)], ephemeral: true });
    }

    if (command === 'serverowner') {
        const config = await getGuildConfig(guild.id);
        const desc   = config?.serverOwner
            ? `<@${config.serverOwner}> is the current server owner for **${guild.name}**.\n\nThey can run \`/authorizebot\` and \`/deauthorizebot\` for this server.`
            : `No server owner is set for **${guild.name}**.\n\nOnly global bot owners can authorize bots until one is assigned with \`/setserverowner\`.`;
        return interaction.reply({ embeds: [infoEmbed('👑 Server Owner', desc, 0x5865F2)], ephemeral: true });
    }

    // ── bot authorization ─────────────────────────────────────────────────────

    if (command === 'authorizebot') {
        if (!(await isServerOwner(user.id, guild.id))) {
            return interaction.reply({ embeds: [infoEmbed('❌ No Permission', 'Only the server owner (or global bot owners) can authorize bots for this server.', 0xE03C3C)], ephemeral: true });
        }
        const botId = interaction.options.getString('botid').trim();
        const reason = interaction.options.getString('reason') ?? 'No reason provided';
        if (!/^\d{17,20}$/.test(botId)) {
            return interaction.reply({ embeds: [infoEmbed('❌ Invalid ID', 'Provide a valid 17-20 digit Discord user ID.', 0xE03C3C)], ephemeral: true });
        }
        await GuildConfig.findOneAndUpdate(
            { guildId: guild.id },
            { $set: { guildId: guild.id }, $addToSet: { authorizedBots: botId } },
            { upsert: true }
        );
        await sendLog(guild, infoEmbed('🤖 Bot Authorized', `Bot \`${botId}\` has been pre-authorized to join.`, 0x57F287, [
            { name: 'Bot ID',      value: botId,         inline: true },
            { name: 'Authorized By', value: `${user.tag}`, inline: true },
            { name: 'Reason',      value: reason,        inline: false }
        ]), `auth-bot:${botId}`);
        return interaction.reply({
            embeds: [infoEmbed('✅ Bot Authorized', `Bot \`${botId}\` is now allowed to join this server.\n\nIf a non-authorized bot joins, it will be **automatically kicked**.`, 0x57F287)],
            ephemeral: true
        });
    }

    if (command === 'deauthorizebot') {
        if (!(await isServerOwner(user.id, guild.id))) {
            return interaction.reply({ embeds: [infoEmbed('❌ No Permission', 'Only the server owner (or global bot owners) can de-authorize bots for this server.', 0xE03C3C)], ephemeral: true });
        }
        const botId = interaction.options.getString('botid').trim();
        if (!/^\d{17,20}$/.test(botId)) {
            return interaction.reply({ embeds: [infoEmbed('❌ Invalid ID', 'Provide a valid 17-20 digit Discord user ID.', 0xE03C3C)], ephemeral: true });
        }
        await GuildConfig.findOneAndUpdate({ guildId: guild.id }, { $pull: { authorizedBots: botId } });
        await sendLog(guild, infoEmbed('🤖 Bot De-authorized', `Bot \`${botId}\` removed from the authorized list.`, 0xFFA500, [
            { name: 'Bot ID', value: botId,         inline: true },
            { name: 'By',     value: `${user.tag}`, inline: true }
        ]), `deauth-bot:${botId}`);
        return interaction.reply({ embeds: [infoEmbed('✅ Bot De-authorized', `Bot \`${botId}\` has been removed from the authorized list.`, 0xFFA500)], ephemeral: true });
    }

    if (command === 'authorizedbots') {
        const config  = await getGuildConfig(guild.id);
        const botList = config?.authorizedBots?.length
            ? config.authorizedBots.map(id => `\`${id}\``).join('\n')
            : 'No bots authorized. Any bot added by a whitelisted member will be **kicked**.';
        return interaction.reply({
            embeds: [infoEmbed('🤖 Authorized Bots', botList, 0x5865F2, [
                { name: 'ℹ️ How it works', value: 'Run `/authorizebot <id>` before adding a bot to this server. Any bot joining without pre-authorization will be automatically kicked, even if added by a whitelisted member.', inline: false }
            ])],
            ephemeral: true
        });
    }

    // ── server customization ──────────────────────────────────────────────────

    if (command === 'setjoinrole') {
        const role = interaction.options.getRole('role');
        await GuildConfig.findOneAndUpdate({ guildId: guild.id }, { $set: { guildId: guild.id, joinRole: role?.id ?? null } }, { upsert: true });
        const msg = role ? `${role} will be given to every user who joins.` : 'Join role disabled.';
        await sendLog(guild, infoEmbed('👋 Join Role Updated', msg, 0x57F287, [{ name: 'By', value: `${user.tag}`, inline: true }]), `setjoinrole:${user.id}`);
        return interaction.reply({ embeds: [infoEmbed('✅ Join Role Set', msg, 0x57F287)], ephemeral: true });
    }

    if (command === 'setbotrole') {
        const role = interaction.options.getRole('role');
        await GuildConfig.findOneAndUpdate({ guildId: guild.id }, { $set: { guildId: guild.id, botRole: role?.id ?? null } }, { upsert: true });
        const msg = role ? `${role} will be given to authorized bots when they join.` : 'Bot role disabled.';
        await sendLog(guild, infoEmbed('🤖 Bot Role Updated', msg, 0x57F287, [{ name: 'By', value: `${user.tag}`, inline: true }]), `setbotrole:${user.id}`);
        return interaction.reply({ embeds: [infoEmbed('✅ Bot Role Set', msg, 0x57F287)], ephemeral: true });
    }

    if (command === 'setmutedrole') {
        const role = interaction.options.getRole('role');
        await GuildConfig.findOneAndUpdate({ guildId: guild.id }, { $set: { guildId: guild.id, mutedRole: role.id } }, { upsert: true });
        await sendLog(guild, infoEmbed('🔇 Muted Role Updated', `Set to ${role}.`, 0x57F287, [{ name: 'By', value: `${user.tag}`, inline: true }]), `setmutedrole:${user.id}`);
        return interaction.reply({ embeds: [infoEmbed('✅ Muted Role Set', `${role} will be used for mutes.`, 0x57F287)], ephemeral: true });
    }

    if (command === 'mute') {
        const target = interaction.options.getUser('user');
        const reason = interaction.options.getString('reason') ?? 'No reason provided';
        const config = await getGuildConfig(guild.id);
        if (!config?.mutedRole) return interaction.reply({ embeds: [infoEmbed('❌ No Muted Role', 'Set one with `/setmutedrole` first.', 0xE03C3C)], ephemeral: true });
        const targetMember = await guild.members.fetch(target.id).catch(() => null);
        if (!targetMember) return interaction.reply({ embeds: [infoEmbed('❌ User Not Found', 'That user is not in this server.', 0xE03C3C)], ephemeral: true });
        if (await isWhitelisted(targetMember)) return interaction.reply({ embeds: [infoEmbed('❌ Cannot Mute', 'That user is whitelisted.', 0xE03C3C)], ephemeral: true });
        try {
            await targetMember.roles.add(config.mutedRole, reason);
            await sendLog(guild, warnEmbed('🔇 Member Muted', `${target.tag} was muted.`, [
                { name: 'User',   value: `${target.tag} (${target.id})`, inline: true },
                { name: 'By',     value: `${user.tag}`,                  inline: true },
                { name: 'Reason', value: reason,                         inline: false }
            ]), `mute:${target.id}`);
            return interaction.reply({ embeds: [infoEmbed('🔇 Muted', `${target.tag} has been muted.`, 0xFFA500)], ephemeral: true });
        } catch (err) {
            return interaction.reply({ embeds: [infoEmbed('❌ Failed', err.message, 0xE03C3C)], ephemeral: true });
        }
    }

    if (command === 'unmute') {
        const target = interaction.options.getUser('user');
        const config = await getGuildConfig(guild.id);
        if (!config?.mutedRole) return interaction.reply({ embeds: [infoEmbed('❌ No Muted Role', 'Set one with `/setmutedrole` first.', 0xE03C3C)], ephemeral: true });
        const targetMember = await guild.members.fetch(target.id).catch(() => null);
        if (!targetMember) return interaction.reply({ embeds: [infoEmbed('❌ User Not Found', 'That user is not in this server.', 0xE03C3C)], ephemeral: true });
        try {
            await targetMember.roles.remove(config.mutedRole, `Unmuted by ${user.tag}`);
            await sendLog(guild, infoEmbed('🔊 Member Unmuted', `${target.tag} was unmuted.`, 0x57F287, [
                { name: 'User', value: `${target.tag} (${target.id})`, inline: true },
                { name: 'By',   value: `${user.tag}`,                  inline: true }
            ]), `unmute:${target.id}`);
            return interaction.reply({ embeds: [infoEmbed('🔊 Unmuted', `${target.tag} has been unmuted.`, 0x57F287)], ephemeral: true });
        } catch (err) {
            return interaction.reply({ embeds: [infoEmbed('❌ Failed', err.message, 0xE03C3C)], ephemeral: true });
        }
    }

    if (command === 'setlinkfilter') {
        const enabled   = interaction.options.getBoolean('enabled');
        const whitelist = interaction.options.getString('whitelist');
        const wlList    = whitelist ? whitelist.split(',').map(s => s.trim()).filter(Boolean) : undefined;
        const update    = { linkFilter: enabled };
        if (wlList !== undefined) update.linkWhitelist = wlList;
        await GuildConfig.findOneAndUpdate({ guildId: guild.id }, { $set: { guildId: guild.id, ...update } }, { upsert: true });
        const wlText = wlList?.length ? `\nAllowed: \`${wlList.join('`, `')}\`` : '';
        const msg    = `Link filter **${enabled ? 'enabled' : 'disabled'}**.${wlText}`;
        await sendLog(guild, infoEmbed('🔗 Link Filter Updated', msg, 0x57F287, [{ name: 'By', value: `${user.tag}`, inline: true }]), `linkfilter:${user.id}`);
        return interaction.reply({ embeds: [infoEmbed('✅ Link Filter', msg, enabled ? 0x57F287 : 0xFFA500)], ephemeral: true });
    }

    if (command === 'setantihoisting') {
        const enabled  = interaction.options.getBoolean('enabled');
        const nickname = interaction.options.getString('nickname') ?? 'Moderated Name';
        await GuildConfig.findOneAndUpdate({ guildId: guild.id }, { $set: { guildId: guild.id, antiHoisting: enabled, hoistingName: nickname } }, { upsert: true });
        const msg = `Anti-hoisting **${enabled ? 'enabled' : 'disabled'}**.${enabled ? ` Replacement name: \`${nickname}\`` : ''}`;
        await sendLog(guild, infoEmbed('🔤 Anti-Hoisting Updated', msg, 0x57F287, [{ name: 'By', value: `${user.tag}`, inline: true }]), `antihoisting:${user.id}`);
        return interaction.reply({ embeds: [infoEmbed('✅ Anti-Hoisting', msg, enabled ? 0x57F287 : 0xFFA500)], ephemeral: true });
    }

    if (command === 'setantiduplicates') {
        const enabled = interaction.options.getBoolean('enabled');
        const limit   = interaction.options.getInteger('limit')  ?? 3;
        const window  = interaction.options.getInteger('window') ?? 5;
        await GuildConfig.findOneAndUpdate({ guildId: guild.id }, { $set: { guildId: guild.id, antiDuplicates: enabled, duplicateLimit: limit, duplicateWindow: window * 1000 } }, { upsert: true });
        const msg = `Duplicate spam detection **${enabled ? 'enabled' : 'disabled'}**.${enabled ? ` Action after ${limit}x in ${window}s.` : ''}`;
        await sendLog(guild, infoEmbed('📋 Anti-Duplicates Updated', msg, 0x57F287, [{ name: 'By', value: `${user.tag}`, inline: true }]), `antidup:${user.id}`);
        return interaction.reply({ embeds: [infoEmbed('✅ Anti-Duplicates', msg, enabled ? 0x57F287 : 0xFFA500)], ephemeral: true });
    }

    if (command === 'setghostpinglog') {
        const enabled = interaction.options.getBoolean('enabled');
        await GuildConfig.findOneAndUpdate({ guildId: guild.id }, { $set: { guildId: guild.id, ghostPingLog: enabled } }, { upsert: true });
        const msg = `Ghost ping logging **${enabled ? 'enabled' : 'disabled'}**.`;
        await sendLog(guild, infoEmbed('👻 Ghost Ping Log Updated', msg, 0x57F287, [{ name: 'By', value: `${user.tag}`, inline: true }]), `ghostping:${user.id}`);
        return interaction.reply({ embeds: [infoEmbed('✅ Ghost Ping Log', msg, enabled ? 0x57F287 : 0xFFA500)], ephemeral: true });
    }

    if (command === 'setscreening') {
        const enabled = interaction.options.getBoolean('enabled');
        await GuildConfig.findOneAndUpdate({ guildId: guild.id }, { $set: { guildId: guild.id, screening: enabled } }, { upsert: true });
        const msg = `Join screening **${enabled ? 'enabled' : 'disabled'}**.`;
        await sendLog(guild, infoEmbed(`🔍 Screening ${enabled ? 'Enabled' : 'Disabled'}`, msg, enabled ? 0x57F287 : 0xFFA500, [{ name: 'By', value: `${user.tag}`, inline: true }]), `screening:${user.id}`);
        return interaction.reply({ embeds: [infoEmbed('✅ Screening', msg, enabled ? 0x57F287 : 0xFFA500)], ephemeral: true });
    }

    // ── role connections ──────────────────────────────────────────────────────

    if (command === 'roleconnectionadd') {
        const key  = interaction.options.getString('connection_key').trim().toLowerCase();
        const role = interaction.options.getRole('role');
        const config   = await getGuildConfig(guild.id);
        const existing = config?.roleConnections ?? [];
        if (existing.length >= 5) {
            return interaction.reply({ embeds: [infoEmbed('❌ Limit Reached', 'Max 5 role connection rules per server.', 0xE03C3C)], ephemeral: true });
        }
        if (existing.find(r => r.connectionKey === key)) {
            return interaction.reply({ embeds: [infoEmbed('❌ Already Exists', `A rule for \`${key}\` already exists. Remove it first.`, 0xE03C3C)], ephemeral: true });
        }
        await GuildConfig.findOneAndUpdate(
            { guildId: guild.id },
            { $set: { guildId: guild.id }, $push: { roleConnections: { connectionKey: key, roleId: role.id } } },
            { upsert: true }
        );
        await sendLog(guild, infoEmbed('🔗 Role Connection Added', `\`${key}\` → ${role}`, 0x57F287, [{ name: 'By', value: `${user.tag}`, inline: true }]), `rc-add:${key}`);
        return interaction.reply({ embeds: [infoEmbed('✅ Rule Added', `Users with \`${key}\` verified will receive ${role}.`, 0x57F287)], ephemeral: true });
    }

    if (command === 'roleconnectionremove') {
        const key = interaction.options.getString('connection_key').trim().toLowerCase();
        await GuildConfig.findOneAndUpdate({ guildId: guild.id }, { $pull: { roleConnections: { connectionKey: key } } });
        await sendLog(guild, infoEmbed('🔗 Role Connection Removed', `Rule for \`${key}\` removed.`, 0xFFA500, [{ name: 'By', value: `${user.tag}`, inline: true }]), `rc-remove:${key}`);
        return interaction.reply({ embeds: [infoEmbed('✅ Rule Removed', `Role connection rule for \`${key}\` removed.`, 0xFFA500)], ephemeral: true });
    }

    if (command === 'roleconnectionlist') {
        const config = await getGuildConfig(guild.id);
        const rules  = config?.roleConnections ?? [];
        const desc   = rules.length
            ? rules.map(r => `\`${r.connectionKey}\` → <@&${r.roleId}>`).join('\n')
            : 'No rules configured.';
        return interaction.reply({ embeds: [infoEmbed('🔗 Role Connections', desc, 0x5865F2)], ephemeral: true });
    }

    if (command === 'serverconfig') {
        const config = await getGuildConfig(guild.id);
        const tc     = await getTicketConfig(guild.id);
        const fields = [
            { name: '📋 Log Channel',       value: config?.logChannel    ? `<#${config.logChannel}>`    : 'Not set', inline: true },
            { name: '🔔 Alert Role',         value: config?.alertRole     ? `<@&${config.alertRole}>`    : 'Not set', inline: true },
            { name: '🛡️ Whitelist Role',    value: config?.whitelistRole ? `<@&${config.whitelistRole}>` : 'Not set', inline: true },
            { name: '👋 Join Role',          value: config?.joinRole      ? `<@&${config.joinRole}>`     : 'Not set', inline: true },
            { name: '🤖 Bot Role',           value: config?.botRole       ? `<@&${config.botRole}>`      : 'Not set', inline: true },
            { name: '🔇 Muted Role',         value: config?.mutedRole     ? `<@&${config.mutedRole}>`    : 'Not set', inline: true },
            { name: '🔒 Raid Mode',          value: raidMode[guild.id]    ? '🔴 Active'  : '🟢 Inactive', inline: true },
            { name: '🔍 Screening',          value: config?.screening !== false ? '🟢 On' : '🔴 Off',    inline: true },
            { name: '🔗 Link Filter',        value: config?.linkFilter    ? '🟢 On'      : '🔴 Off',    inline: true },
            { name: '🔤 Anti-Hoisting',      value: config?.antiHoisting  ? '🟢 On'      : '🔴 Off',    inline: true },
            { name: '📋 Anti-Duplicates',    value: config?.antiDuplicates ? '🟢 On'     : '🔴 Off',    inline: true },
            { name: '👻 Ghost Ping Log',     value: config?.ghostPingLog  ? '🟢 On'      : '🔴 Off',    inline: true },
            { name: '🎫 Ticket System',      value: tc                    ? '🟢 Configured' : '🔴 Not set', inline: true },
            { name: '🔗 Role Connections',   value: `${config?.roleConnections?.length ?? 0} rule(s)`,   inline: true },
            { name: '🤖 Authorized Bots',    value: `${config?.authorizedBots?.length ?? 0} bot(s)`,                              inline: true },
            { name: '👑 Server Owner',        value: config?.serverOwner ? `<@${config.serverOwner}>` : 'Not set',                 inline: true }
        ];
        return interaction.reply({ embeds: [infoEmbed('⚙️ Server Configuration', `Config for **${guild.name}**`, 0x5865F2, fields)], ephemeral: true });
    }

    // ── ticket commands ───────────────────────────────────────────────────────

    if (command === 'ticketsetup') {
        const panelChannel = interaction.options.getChannel('panel_channel');
        const category     = interaction.options.getChannel('category');
        const logChannel   = interaction.options.getChannel('log_channel');
        const supportRole  = interaction.options.getRole('support_role');
        const panelTitle   = interaction.options.getString('panel_title')   ?? '🎫 Support Tickets';
        const panelDesc    = interaction.options.getString('panel_desc')    ?? 'Click the button below to open a support ticket.';
        const panelColor   = interaction.options.getString('panel_color')   ?? '#5865F2';
        const buttonLabel  = interaction.options.getString('button_label')  ?? 'Open a Ticket';
        const buttonEmoji  = interaction.options.getString('button_emoji')  ?? '🎫';
        const openMessage  = interaction.options.getString('open_message')  ?? 'Welcome! Please describe your issue and a staff member will be with you shortly.';
        const maxPerUser   = interaction.options.getInteger('max_per_user') ?? 1;

        const colorClean = panelColor.replace('#', '');
        if (!/^[0-9A-Fa-f]{6}$/.test(colorClean)) {
            return interaction.reply({ embeds: [infoEmbed('❌ Invalid Color', 'Use a format like `#FF0000`.', 0xE03C3C)], ephemeral: true });
        }
        if (category.type !== ChannelType.GuildCategory) {
            return interaction.reply({ embeds: [infoEmbed('❌ Not a Category', 'The `category` option must be a channel category.', 0xE03C3C)], ephemeral: true });
        }

        const config = await TicketConfig.findOneAndUpdate(
            { guildId: guild.id },
            { $set: { guildId: guild.id, panelChannelId: panelChannel.id, categoryId: category.id, logChannelId: logChannel.id, supportRoleId: supportRole.id, panelTitle, panelDescription: panelDesc, panelColor: colorClean, buttonLabel, buttonEmoji, openMessage, maxOpenPerUser: maxPerUser } },
            { upsert: true, new: true }
        );

        await sendTicketPanel(guild, config, panelChannel.id);
        return interaction.reply({
            embeds: [infoEmbed('✅ Ticket System Configured', '', 0x57F287, [
                { name: 'Panel Channel', value: `${panelChannel}`, inline: true },
                { name: 'Category',      value: category.name,     inline: true },
                { name: 'Log Channel',   value: `${logChannel}`,   inline: true },
                { name: 'Support Role',  value: `${supportRole}`,  inline: true },
                { name: 'Button Label',  value: buttonLabel,       inline: true },
                { name: 'Max / User',    value: `${maxPerUser}`,   inline: true }
            ])],
            ephemeral: true
        });
    }

    if (command === 'ticketpanel') {
        const ticketCfg = await getTicketConfig(guild.id);
        if (!ticketCfg) return interaction.reply({ embeds: [infoEmbed('❌ Not Configured', 'Run `/ticketsetup` first.', 0xE03C3C)], ephemeral: true });
        await sendTicketPanel(guild, ticketCfg);
        return interaction.reply({ embeds: [infoEmbed('✅ Panel Refreshed', 'The ticket panel has been updated.', 0x57F287)], ephemeral: true });
    }

    if (command === 'ticketclose') {
        const ticket = await Ticket.findOne({ guildId: guild.id, channelId: interaction.channelId, status: 'open' });
        if (!ticket) return interaction.reply({ embeds: [infoEmbed('❌ Not a Ticket', 'This channel is not an open ticket.', 0xE03C3C)], ephemeral: true });
        await interaction.deferReply();
        await closeTicket(interaction.channel, guild, user);
        return;
    }

    if (command === 'ticketadd') {
        const target = interaction.options.getUser('user');
        const ticket = await Ticket.findOne({ guildId: guild.id, channelId: interaction.channelId });
        if (!ticket) return interaction.reply({ embeds: [infoEmbed('❌ Not a Ticket', 'This channel is not a ticket.', 0xE03C3C)], ephemeral: true });
        try {
            await interaction.channel.permissionOverwrites.edit(target.id, { ViewChannel: true, SendMessages: true, ReadMessageHistory: true });
            return interaction.reply({ embeds: [infoEmbed('✅ User Added', `<@${target.id}> can now see this ticket.`, 0x57F287)] });
        } catch {
            return interaction.reply({ embeds: [infoEmbed('❌ Failed', 'Could not add user to the ticket.', 0xE03C3C)], ephemeral: true });
        }
    }

    if (command === 'ticketremove') {
        const target = interaction.options.getUser('user');
        const ticket = await Ticket.findOne({ guildId: guild.id, channelId: interaction.channelId });
        if (!ticket) return interaction.reply({ embeds: [infoEmbed('❌ Not a Ticket', 'This channel is not a ticket.', 0xE03C3C)], ephemeral: true });
        if (target.id === ticket.userId) return interaction.reply({ embeds: [infoEmbed('❌ Cannot Remove Owner', 'You cannot remove the ticket owner.', 0xE03C3C)], ephemeral: true });
        try {
            await interaction.channel.permissionOverwrites.edit(target.id, { ViewChannel: false });
            return interaction.reply({ embeds: [infoEmbed('✅ User Removed', `<@${target.id}> was removed from this ticket.`, 0xFFA500)] });
        } catch {
            return interaction.reply({ embeds: [infoEmbed('❌ Failed', 'Could not remove user from the ticket.', 0xE03C3C)], ephemeral: true });
        }
    }
});

// ─── member join ──────────────────────────────────────────────────────────────

client.on('guildMemberAdd', async member => {
    const guildId = member.guild.id;

    // global blacklist — immediate ban
    if (isGloballyBlacklisted(member.id)) {
        try {
            await member.ban({ reason: 'Global blacklist' });
            await sendLog(member.guild, alertEmbed('⛔ Global Blacklist — Auto-Banned',
                `<@${member.id}> joined but is on the global blacklist and was immediately banned.`, [
                { name: 'User', value: `${member.user.tag} (${member.id})`, inline: true }
            ]), `gbl-ban:${member.id}`);
        } catch {}
        return;
    }

    const config = await getGuildConfig(guildId);

    // ── FIX: bot join — check authorization list FIRST ────────────────────────
    if (member.user.bot) {
        const isAuthorized = config?.authorizedBots?.includes(member.id) ?? false;

        if (!isAuthorized) {
            // Bot was not pre-authorized — kick it regardless of who added it
            try {
                await member.kick('Unauthorized bot — not on the authorized list');
                const entry = await fetchAuditEntry(member.guild, AuditLogEvent.BotAdd, member.id);
                const addedBy = entry ? `<@${entry.executor.id}> (${entry.executor.tag ?? entry.executor.id})` : 'Unknown';
                await sendLog(member.guild, alertEmbed('🚨 Unauthorized Bot Kicked',
                    `Bot \`${member.user.tag}\` (${member.id}) joined without pre-authorization and was kicked.`, [
                    { name: 'Bot',      value: `${member.user.tag} (${member.id})`, inline: true },
                    { name: 'Added By', value: addedBy,                             inline: true },
                    { name: 'Action',   value: 'Bot kicked — use `/authorizebot` before adding bots', inline: false }
                ]), `unauth-bot:${member.id}`);
            } catch {}
            return;
        }

        // Authorized bot — check if the person who added it was whitelisted anyway
        const entry    = await fetchAuditEntry(member.guild, AuditLogEvent.BotAdd, member.id);
        const executor = entry ? await member.guild.members.fetch(entry.executor.id).catch(() => null) : null;

        if (executor && !(await isWhitelisted(executor))) {
            // Even if the bot was authorized, only whitelisted members may add bots
            try {
                await member.kick('Bot added by non-whitelisted member');
                await stripRoles(executor);
                await sendLog(member.guild, alertEmbed('🚨 Bot Added by Non-Whitelisted Member',
                    `${executor.user.tag} added bot \`${member.user.tag}\` without being on the whitelist.`, [
                    { name: 'Executor', value: `${executor.user.tag} (${executor.id})`, inline: true },
                    { name: 'Bot',      value: `${member.user.tag} (${member.id})`,     inline: true },
                    { name: 'Action',   value: 'Bot kicked, executor roles stripped',   inline: false }
                ]), `bot-add:${executor.id}`);
            } catch {}
            return;
        }

        // assign bot role if configured
        if (config?.botRole) {
            try { await member.roles.add(config.botRole); } catch {}
        }
        return;
    }

    // skip checks for whitelisted human members
    if (await isWhitelisted(member)) {
        if (config?.joinRole) {
            try { await member.roles.add(config.joinRole); } catch {}
        }
        return;
    }

    // join rate / raid detection
    if (!joins[guildId]) joins[guildId] = [];
    joins[guildId].push(Date.now());
    joins[guildId] = joins[guildId].filter(t => Date.now() - t < JOIN_TIME);

    if (joins[guildId].length >= JOIN_LIMIT && !raidMode[guildId]) {
        raidMode[guildId] = true;
        await lockServer(member.guild);
        await sendLog(member.guild, alertEmbed('🚨 Raid Detected!',
            `${joins[guildId].length} users joined within ${JOIN_TIME / 1000}s. Server locked.`, [
            { name: 'Action', value: 'Server locked, slowmode enabled', inline: false }
        ]));
    }

    // screening checks
    if (config?.screening !== false) {
        if (!member.user.avatar) {
            try {
                await dmAndKick(member, 'No profile picture', 'This server requires a profile picture. Please set one and try again.');
                await sendLog(member.guild, warnEmbed('⚠️ No Profile Picture — Kicked', `${member.user.tag} was kicked.`, [
                    { name: 'User', value: `${member.user.tag} (${member.id})`, inline: true }
                ]), `no-pfp:${member.id}`);
            } catch {}
            return;
        }

        const accountAge = Date.now() - member.user.createdTimestamp;
        if (accountAge < ACCOUNT_AGE_LIMIT) {
            try {
                await dmAndKick(member, 'Account too new', `This server requires accounts to be at least 3 days old. Your account is ${Math.floor(accountAge / 86400000)} day(s) old.`);
                await sendLog(member.guild, warnEmbed('⚠️ New Account — Kicked', `${member.user.tag} was kicked.`, [
                    { name: 'User',        value: `${member.user.tag} (${member.id})`,     inline: true },
                    { name: 'Account Age', value: `${Math.floor(accountAge / 86400000)}d`, inline: true }
                ]), `new-acct:${member.id}`);
            } catch {}
            return;
        }

        const matchedPattern = SUSPICIOUS_USERNAME_PATTERNS.find(p => p.test(member.user.username));
        if (matchedPattern) {
            try {
                await dmAndKick(member, 'Suspicious username', 'Your username was flagged by our auto-moderation. Please change it and contact an admin if you believe this is a mistake.');
                await sendLog(member.guild, warnEmbed('⚠️ Suspicious Username — Kicked', `${member.user.tag} was kicked.`, [
                    { name: 'User',     value: `${member.user.tag} (${member.id})`, inline: true },
                    { name: 'Username', value: `\`${member.user.username}\``,        inline: true }
                ]), `sus-name:${member.id}`);
            } catch {}
            return;
        }
    }

    // anti-hoisting on join
    if (config?.antiHoisting && HOIST_PATTERN.test(member.user.username)) {
        try { await member.setNickname(config.hoistingName); } catch {}
    }

    // assign join role
    if (config?.joinRole) {
        try { await member.roles.add(config.joinRole); } catch {}
    }
});

// ─── message protection ───────────────────────────────────────────────────────

client.on('messageCreate', async message => {
    if (!message.guild || message.author.bot) return;

    if (isGloballyBlacklisted(message.author.id)) {
        try {
            await message.delete();
            await message.guild.members.ban(message.author.id, { reason: 'Global blacklist' });
        } catch {}
        return;
    }

    const mentionOnly = new RegExp(`^<@!?${client.user.id}>\\s*$`);
    if (mentionOnly.test(message.content.trim())) {
        return message.reply({
            embeds: [new EmbedBuilder()
                .setTitle('👋 Hello!')
                .setColor(0x5865F2)
                .setDescription("I am **Pierce's Anti-Raid Bot**!\nContact **pierceunlimited** on Discord for bug reports.")
                .setThumbnail(client.user.displayAvatarURL())
                .setFooter({ text: FOOTER_TEXT })
                .setTimestamp()
            ]
        });
    }

    if (await isWhitelisted(message.member)) return;

    const guildId = message.guild.id;
    const userId  = message.author.id;
    const config  = await getGuildConfig(guildId);

    // cache for ghost-ping detection
    if (!messageCache[message.channel.id]) messageCache[message.channel.id] = [];
    messageCache[message.channel.id].push({
        authorId:  message.author.id,
        content:   message.content,
        id:        message.id,
        timestamp: Date.now(),
        mentions:  [...message.mentions.users.keys(), ...message.mentions.roles.keys()]
    });
    if (messageCache[message.channel.id].length > 50) messageCache[message.channel.id].shift();

    // link filter
    if (config?.linkFilter) {
        const inviteMatches = [...(message.content.matchAll(INVITE_PATTERN) ?? [])];
        const urlMatches    = [...(message.content.matchAll(URL_PATTERN)    ?? [])];
        const whitelist     = config.linkWhitelist ?? [];
        const hasBlockedInvite = inviteMatches.some(m => !whitelist.includes(m[1]));
        const hasBlockedUrl    = urlMatches.some(m => !whitelist.some(w => m[0].includes(w)));
        if (hasBlockedInvite || hasBlockedUrl) {
            try {
                await message.delete();
                await sendLog(message.guild, warnEmbed('🔗 Link Blocked', `${message.author.tag} posted a blocked link.`, [
                    { name: 'User',    value: `${message.author.tag} (${userId})`, inline: true },
                    { name: 'Channel', value: `${message.channel}`,                inline: true }
                ]), `link-block:${userId}`);
            } catch {}
            return;
        }
    }

    // duplicate / copy-paste spam
    if (config?.antiDuplicates) {
        const content = message.content.trim().toLowerCase();
        if (content.length > 0) {
            if (!duplicateTracker[guildId]) duplicateTracker[guildId] = {};
            const dt     = duplicateTracker[guildId];
            const now    = Date.now();
            const window = config.duplicateWindow ?? 5000;
            const limit  = config.duplicateLimit  ?? 3;
            if (!dt[userId] || dt[userId].lastMsg !== content || now - dt[userId].resetAt > window) {
                dt[userId] = { lastMsg: content, count: 1, resetAt: now };
            } else {
                dt[userId].count += 1;
                if (dt[userId].count >= limit) {
                    try {
                        await message.member.ban({ reason: 'Duplicate/copy-paste spam' });
                        await sendLog(message.guild, alertEmbed('🚨 Duplicate Spam Detected', `${message.author.tag} was banned for sending the same message ${dt[userId].count}x.`, [
                            { name: 'User',    value: `${message.author.tag} (${userId})`, inline: true },
                            { name: 'Count',   value: `${dt[userId].count}`,               inline: true },
                            { name: 'Message', value: content.slice(0, 200),               inline: false }
                        ]), `dup-spam:${userId}`);
                    } catch {}
                    return;
                }
            }
        }
    }

    // embed spam
    if (message.embeds.length > 0) {
        if (!embedTracker[guildId]) embedTracker[guildId] = {};
        if (!embedTracker[guildId][userId]) embedTracker[guildId][userId] = { count: 0, lastReset: Date.now() };
        const et = embedTracker[guildId][userId];
        if (Date.now() - et.lastReset > EMBED_SPAM_TIME) { et.count = 0; et.lastReset = Date.now(); }
        et.count += message.embeds.length;
        if (et.count >= EMBED_SPAM_LIMIT) {
            try {
                await message.member.ban({ reason: 'Embed spam' });
                await message.delete();
                await sendLog(message.guild, alertEmbed('🚨 Embed Spam Detected', `${message.author.tag} was banned.`, [
                    { name: 'User', value: `${message.author.tag} (${userId})`, inline: true }
                ]), `embed-spam:${userId}`);
            } catch {}
            return;
        }
    }

    // mention / ping spam
    const userMentions   = message.mentions.users.size;
    const roleMentions   = message.mentions.roles.size;
    const everyonePing   = message.mentions.everyone;
    const hiddenEveryone = message.content.toLowerCase().includes('||@everyone||');
    const embedPing      = message.embeds.some(e => e.title?.includes('@everyone') || e.description?.includes('@everyone'));

    if (!mentionTracker[guildId]) mentionTracker[guildId] = {};
    if (!mentionTracker[guildId][userId]) mentionTracker[guildId][userId] = { users: 0, roles: 0, everyone: 0, lastReset: Date.now() };
    const tracker = mentionTracker[guildId][userId];
    if (Date.now() - tracker.lastReset > PING_TIME) { tracker.users = 0; tracker.roles = 0; tracker.everyone = 0; tracker.lastReset = Date.now(); }

    tracker.users += userMentions;
    tracker.roles += roleMentions;
    if (everyonePing || hiddenEveryone || embedPing) tracker.everyone += 1;

    if (tracker.everyone >= EVERYONE_LIMIT) {
        try {
            await message.member.ban({ reason: '@everyone spam' });
            await message.delete();
            await sendLog(message.guild, alertEmbed('🚨 @everyone Spam Detected', `${message.author.tag} was banned.`, [
                { name: 'User', value: `${message.author.tag} (${userId})`, inline: true }
            ]), `everyone-spam:${userId}`);
        } catch {}
        return;
    }
    if (tracker.users >= USER_PING_LIMIT) {
        try {
            await message.member.ban({ reason: 'User mention spam' });
            await message.delete();
            await sendLog(message.guild, alertEmbed('🚨 Mass User Mention Detected', `${message.author.tag} was banned.`, [
                { name: 'User',     value: `${message.author.tag} (${userId})`, inline: true },
                { name: 'Mentions', value: `${tracker.users}`,                   inline: true }
            ]), `user-mention:${userId}`);
        } catch {}
        return;
    }
    if (tracker.roles >= ROLE_PING_LIMIT) {
        try {
            await message.member.ban({ reason: 'Role mention spam' });
            await message.delete();
            await sendLog(message.guild, alertEmbed('🚨 Mass Role Mention Detected', `${message.author.tag} was banned.`, [
                { name: 'User',     value: `${message.author.tag} (${userId})`, inline: true },
                { name: 'Mentions', value: `${tracker.roles}`,                   inline: true }
            ]), `role-mention:${userId}`);
        } catch {}
        return;
    }
});

// ─── ghost ping detection ─────────────────────────────────────────────────────

client.on('messageDelete', async message => {
    if (!message.guild || !message.author || message.author.bot) return;
    const config = await getGuildConfig(message.guild.id);
    if (!config?.ghostPingLog) return;
    const cached = messageCache[message.channel.id]?.find(m => m.id === message.id);
    if (!cached || cached.mentions.length === 0) return;
    await sendLog(message.guild, warnEmbed('👻 Ghost Ping Detected', `${message.author.tag} deleted a message that contained mentions.`, [
        { name: 'User',     value: `${message.author.tag} (${message.author.id})`,               inline: true },
        { name: 'Channel',  value: `${message.channel}`,                                          inline: true },
        { name: 'Mentions', value: cached.mentions.map(id => `<@${id}>`).join(', ').slice(0, 1024), inline: false }
    ]), `ghost-ping:${message.author.id}`);
});

// ─── anti-hoisting on nickname change ────────────────────────────────────────

client.on('guildMemberUpdate', async (oldMember, newMember) => {
    const config = await getGuildConfig(newMember.guild.id);
    if (!config?.antiHoisting) return;
    const displayName = newMember.nickname ?? newMember.user.username;
    if (HOIST_PATTERN.test(displayName) && !(await isWhitelisted(newMember))) {
        try {
            await newMember.setNickname(config.hoistingName);
            await sendLog(newMember.guild, warnEmbed('🔤 Anti-Hoisting — Nickname Changed', `${newMember.user.tag}'s nickname was reset.`, [
                { name: 'User', value: `${newMember.user.tag} (${newMember.id})`, inline: true },
                { name: 'Was',  value: `\`${displayName}\``,                      inline: true },
                { name: 'Now',  value: `\`${config.hoistingName}\``,              inline: true }
            ]), `hoist:${newMember.id}`);
        } catch {}
    }
});

// ─── channel events ───────────────────────────────────────────────────────────

async function handleChannelAction(guild, executorId) {
    const count = trackAction(channelActions, guild.id, executorId, CHANNEL_NUKE_TIME);
    if (count >= CHANNEL_NUKE_LIMIT) {
        await punishExecutor(guild, executorId, alertEmbed('🚨 Channel Nuke Detected', `<@${executorId}> made ${count} rapid channel modifications.`, [
            { name: 'Executor', value: `<@${executorId}>`,                           inline: true },
            { name: 'Actions',  value: `${count} in ${CHANNEL_NUKE_TIME / 1000}s`,  inline: true }
        ]));
    }
}

client.on('channelCreate', async channel => {
    try {
        const entry = await fetchAuditEntry(channel.guild, AuditLogEvent.ChannelCreate);
        if (!entry) return;
        if (channel.type === ChannelType.GuildCategory) {
            const count = trackAction(categoryTracker, channel.guild.id, entry.executor.id, CATEGORY_SPAM_TIME);
            if (count >= CATEGORY_SPAM_LIMIT) {
                await punishExecutor(channel.guild, entry.executor.id, alertEmbed('🚨 Category Spam Detected', `<@${entry.executor.id}> created ${count} categories rapidly.`, [
                    { name: 'Executor', value: `<@${entry.executor.id}>`,                         inline: true },
                    { name: 'Actions',  value: `${count} in ${CATEGORY_SPAM_TIME / 1000}s`,       inline: true }
                ]));
            }
        } else {
            await handleChannelAction(channel.guild, entry.executor.id);
        }
    } catch {}
});

client.on('channelDelete', async channel => {
    try {
        const entry = await fetchAuditEntry(channel.guild, AuditLogEvent.ChannelDelete);
        if (!entry) return;
        await handleChannelAction(channel.guild, entry.executor.id);
    } catch {}
});

client.on('channelUpdate', async (oldChannel, newChannel) => {
    try {
        const oldOverwrites = oldChannel.permissionOverwrites?.cache;
        const newOverwrites = newChannel.permissionOverwrites?.cache;
        if (oldOverwrites && newOverwrites) {
            for (const [id, newOW] of newOverwrites) {
                const oldOW           = oldOverwrites.get(id);
                const gainedDangerous = DANGEROUS_CHANNEL_PERMS.some(flag => !(oldOW?.allow.has(flag) ?? false) && newOW.allow.has(flag));
                if (gainedDangerous) {
                    const entry = await fetchAuditEntry(newChannel.guild, AuditLogEvent.ChannelOverwriteUpdate);
                    if (!entry) break;
                    const member = await newChannel.guild.members.fetch(entry.executor.id).catch(() => null);
                    if (!member || await isWhitelisted(member)) break;
                    try { await newChannel.permissionOverwrites.delete(id); } catch {}
                    await stripRoles(member);
                    await sendLog(newChannel.guild, alertEmbed('🚨 Permission Escalation (Channel)', `${member.user.tag} tried to grant dangerous channel permissions.`, [
                        { name: 'Executor', value: `${member.user.tag} (${member.id})`,  inline: true },
                        { name: 'Channel',  value: newChannel.name,                      inline: true },
                        { name: 'Action',   value: 'Overwrite deleted, roles stripped',  inline: false }
                    ]), `perm-esc:${member.id}`);
                    break;
                }
            }
        }
        const entry = await fetchAuditEntry(newChannel.guild, AuditLogEvent.ChannelUpdate);
        if (!entry) return;
        await handleChannelAction(newChannel.guild, entry.executor.id);
    } catch {}
});

client.on('threadCreate', async thread => {
    try {
        const entry  = await fetchAuditEntry(thread.guild, AuditLogEvent.ThreadCreate);
        if (!entry) return;
        const member = await thread.guild.members.fetch(entry.executor.id).catch(() => null);
        if (!member || await isWhitelisted(member)) return;
        const isForum = thread.parent?.type === ChannelType.GuildForum;
        const tracker = isForum ? forumTracker    : threadTracker;
        const limit   = isForum ? FORUM_SPAM_LIMIT  : THREAD_SPAM_LIMIT;
        const time    = isForum ? FORUM_SPAM_TIME   : THREAD_SPAM_TIME;
        const label   = isForum ? '🚨 Forum Post Spam' : '🚨 Thread Spam';
        const action  = isForum ? 'forum posting'      : 'thread creation';
        const count   = trackAction(tracker, thread.guild.id, entry.executor.id, time);
        if (count >= limit) {
            await punishExecutor(thread.guild, entry.executor.id, alertEmbed(label, `<@${entry.executor.id}> made ${count} rapid ${action} actions.`, [
                { name: 'Executor', value: `${member.user.tag} (${member.id})`, inline: true },
                { name: 'Actions',  value: `${count} in ${time / 1000}s`,       inline: true }
            ]));
        }
    } catch {}
});

client.on('webhookUpdate', async channel => {
    try {
        const entry  = await fetchAuditEntry(channel.guild, AuditLogEvent.WebhookCreate);
        if (!entry) return;
        const member = await channel.guild.members.fetch(entry.executor.id).catch(() => null);
        if (!member || await isWhitelisted(member)) return;
        await member.ban({ reason: 'Webhook abuse' });
        const webhooks = await channel.fetchWebhooks();
        for (const wh of webhooks.values()) { try { await wh.delete(); } catch {} }
        await sendLog(channel.guild, alertEmbed('🚨 Webhook Abuse Detected', `${member.user.tag} was banned for creating an unauthorized webhook.`, [
            { name: 'Executor', value: `${member.user.tag} (${member.id})`, inline: true },
            { name: 'Channel',  value: channel.name,                        inline: true },
            { name: 'Action',   value: 'Banned + webhook deleted',          inline: false }
        ]), `webhook:${member.id}`);
    } catch {}
});

client.on('guildBanAdd', async ban => {
    try {
        const entry    = await fetchAuditEntry(ban.guild, AuditLogEvent.MemberBanAdd, ban.user.id);
        if (!entry) return;
        const executor = await ban.guild.members.fetch(entry.executor.id).catch(() => null);
        if (!executor || await isWhitelisted(executor)) return;
        const count = trackAction(banTracker, ban.guild.id, entry.executor.id, MASS_BAN_TIME);
        if (count >= MASS_BAN_LIMIT) {
            await stripRoles(executor);
            try { await executor.ban({ reason: 'Mass ban detected' }); } catch {}
            await sendLog(ban.guild, alertEmbed('🚨 Mass Ban Detected', `${executor.user.tag} issued ${count} bans in ${MASS_BAN_TIME / 1000}s.`, [
                { name: 'Executor', value: `${executor.user.tag} (${executor.id})`, inline: true },
                { name: 'Bans',     value: `${count}`,                               inline: true },
                { name: 'Action',   value: 'Executor banned',                        inline: false }
            ]), `mass-ban:${executor.id}`);
        }
    } catch {}
});

client.on('guildMemberRemove', async member => {
    // kick detection
    try {
        const kickEntry = await fetchAuditEntry(member.guild, AuditLogEvent.MemberKick, member.id);
        if (kickEntry && Date.now() - kickEntry.createdTimestamp <= 5000) {
            const executor = await member.guild.members.fetch(kickEntry.executor.id).catch(() => null);
            if (executor && !(await isWhitelisted(executor))) {
                const count = trackAction(kickTracker, member.guild.id, kickEntry.executor.id, MASS_KICK_TIME);
                if (count >= MASS_KICK_LIMIT) {
                    await stripRoles(executor);
                    try { await executor.ban({ reason: 'Mass kick detected' }); } catch {}
                    await sendLog(member.guild, alertEmbed('🚨 Mass Kick Detected', `${executor.user.tag} issued ${count} kicks in ${MASS_KICK_TIME / 1000}s.`, [
                        { name: 'Executor', value: `${executor.user.tag} (${executor.id})`, inline: true },
                        { name: 'Kicks',    value: `${count}`,                               inline: true },
                        { name: 'Action',   value: 'Executor banned',                        inline: false }
                    ]), `mass-kick:${executor.id}`);
                }
            }
        }
    } catch {}

    // prune detection
    try {
        const pruneEntry = await fetchAuditEntry(member.guild, AuditLogEvent.MemberPrune);
        if (pruneEntry && Date.now() - pruneEntry.createdTimestamp <= 5000) {
            const executor = await member.guild.members.fetch(pruneEntry.executor.id).catch(() => null);
            if (executor && !(await isWhitelisted(executor))) {
                await stripRoles(executor);
                await sendLog(member.guild, alertEmbed('🚨 Unauthorized Prune', `${executor.user.tag} triggered a member prune.`, [
                    { name: 'Executor',       value: `${executor.user.tag} (${executor.id})`,     inline: true },
                    { name: 'Members Pruned', value: `${pruneEntry.extra?.removed ?? 'unknown'}`, inline: true },
                    { name: 'Action',         value: 'Executor roles stripped',                    inline: false }
                ]), `prune:${executor.id}`);
            }
        }
    } catch {}
});

client.on('roleDelete', async role => {
    try {
        const entry  = await fetchAuditEntry(role.guild, AuditLogEvent.RoleDelete);
        if (!entry) return;
        const member = await role.guild.members.fetch(entry.executor.id).catch(() => null);
        if (!member || await isWhitelisted(member)) return;
        const count = trackAction(roleDeleteTracker, role.guild.id, entry.executor.id, MASS_ROLE_DELETE_TIME);
        if (count >= MASS_ROLE_DELETE_LIMIT) {
            await stripRoles(member);
            await sendLog(role.guild, alertEmbed('🚨 Mass Role Deletion', `${member.user.tag} deleted ${count} roles in ${MASS_ROLE_DELETE_TIME / 1000}s.`, [
                { name: 'Executor', value: `${member.user.tag} (${member.id})`, inline: true },
                { name: 'Deleted',  value: `${count}`,                           inline: true },
                { name: 'Action',   value: 'Executor roles stripped',            inline: false }
            ]), `role-del:${member.id}`);
        }
    } catch {}
});

client.on('emojiDelete', async emoji => {
    try {
        const entry  = await fetchAuditEntry(emoji.guild, AuditLogEvent.EmojiDelete);
        if (!entry) return;
        const member = await emoji.guild.members.fetch(entry.executor.id).catch(() => null);
        if (!member || await isWhitelisted(member)) return;
        const count = trackAction(emojiTracker, emoji.guild.id, entry.executor.id, EMOJI_NUKE_TIME);
        if (count >= EMOJI_NUKE_LIMIT) {
            await stripRoles(member);
            await sendLog(emoji.guild, alertEmbed('🚨 Emoji Nuke Detected', `${member.user.tag} deleted ${count} emojis in ${EMOJI_NUKE_TIME / 1000}s.`, [
                { name: 'Executor', value: `${member.user.tag} (${member.id})`, inline: true },
                { name: 'Deleted',  value: `${count}`,                           inline: true }
            ]), `emoji-nuke:${member.id}`);
        }
    } catch {}
});

client.on('stickerDelete', async sticker => {
    try {
        const entry  = await fetchAuditEntry(sticker.guild, AuditLogEvent.StickerDelete);
        if (!entry) return;
        const member = await sticker.guild.members.fetch(entry.executor.id).catch(() => null);
        if (!member || await isWhitelisted(member)) return;
        const count = trackAction(stickerTracker, sticker.guild.id, entry.executor.id, STICKER_NUKE_TIME);
        if (count >= STICKER_NUKE_LIMIT) {
            await stripRoles(member);
            await sendLog(sticker.guild, alertEmbed('🚨 Sticker Nuke Detected', `${member.user.tag} deleted ${count} stickers in ${STICKER_NUKE_TIME / 1000}s.`, [
                { name: 'Executor', value: `${member.user.tag} (${member.id})`, inline: true },
                { name: 'Deleted',  value: `${count}`,                           inline: true }
            ]), `sticker-nuke:${member.id}`);
        }
    } catch {}
});

client.on('roleUpdate', async (oldRole, newRole) => {
    try {
        const hadAdmin    = oldRole.permissions.has(PermissionsBitField.Flags.Administrator);
        const nowHasAdmin = newRole.permissions.has(PermissionsBitField.Flags.Administrator);
        if (!hadAdmin && nowHasAdmin) {
            const entry  = await fetchAuditEntry(newRole.guild, AuditLogEvent.RoleUpdate);
            if (!entry) return;
            const member = await newRole.guild.members.fetch(entry.executor.id).catch(() => null);
            if (!member || await isWhitelisted(member)) return;
            try { await newRole.setPermissions(oldRole.permissions); } catch {}
            await stripRoles(member);
            await sendLog(newRole.guild, alertEmbed('🚨 Permission Escalation (Role)', `${member.user.tag} tried to grant Administrator to \`${newRole.name}\`.`, [
                { name: 'Executor', value: `${member.user.tag} (${member.id})`,   inline: true },
                { name: 'Role',     value: `\`${newRole.name}\``,                  inline: true },
                { name: 'Action',   value: 'Permission reverted, roles stripped',  inline: false }
            ]), `perm-esc-role:${member.id}`);
        }
    } catch {}
});

client.login(process.env.TOKEN);