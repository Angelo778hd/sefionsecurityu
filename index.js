const { Client, GatewayIntentBits, EmbedBuilder, PermissionsBitField, ActionRowBuilder, ButtonBuilder, ButtonStyle, ChannelType, AuditLogEvent, AttachmentBuilder, ModalBuilder, TextInputBuilder, TextInputStyle, StringSelectMenuBuilder, StringSelectMenuOptionBuilder } = require('discord.js');
const express = require('express');
const mongoose = require('mongoose');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const passport = require('passport');
const DiscordStrategy = require('passport-discord').Strategy;
const path = require('path');
const fs = require('fs');
const sharp = require('sharp');
const Canvas = require('canvas');
require('dotenv').config();

const client = new Client({
    intents: [
        GatewayIntentBits.Guilds,
        GatewayIntentBits.GuildMembers,
        GatewayIntentBits.GuildMessages,
        GatewayIntentBits.GuildBans,
        GatewayIntentBits.MessageContent,
        GatewayIntentBits.GuildInvites,
        GatewayIntentBits.GuildEmojisAndStickers,
        GatewayIntentBits.GuildMessageReactions,
        GatewayIntentBits.DirectMessages,
        GatewayIntentBits.GuildModeration
    ]
});

const app = express();

mongoose.connect(process.env.MONGODB_URI || 'mongodb://localhost:27017/securitybot?retryWrites=true&w=majority', {
    useNewUrlParser: true,
    useUnifiedTopology: true
})
.then(() => {
    console.log('✅ Connesso a MongoDB Atlas con successo!');
})
.catch((error) => {
    console.error('❌ Errore connessione MongoDB:', error.message);
});

const guildSchema = new mongoose.Schema({
    guildId: { type: String, required: true, unique: true },
    ownerId: String,
    botType: { type: String, enum: ['free', 'plus', 'premium'], default: 'free' },
    moderators: [{
        userId: String,
        permissions: {
            manageBans: { type: Boolean, default: false },
            manageKicks: { type: Boolean, default: false },
            manageRoles: { type: Boolean, default: false },
            manageChannels: { type: Boolean, default: false },
            manageMessages: { type: Boolean, default: false },
            viewLogs: { type: Boolean, default: true },
            manageSettings: { type: Boolean, default: false }
        }
    }],
    trustedRoles: [String],
    settings: {
        antiBan: { 
            enabled: { type: Boolean, default: false },
            limit: { type: Number, default: 1 },
            punishmentType: { type: String, enum: ['kick', 'ban', 'timeout'], default: 'ban' },
            timeoutDuration: { type: Number, default: 10 }
        },
        antiKick: { 
            enabled: { type: Boolean, default: false },
            limit: { type: Number, default: 3 },
            punishmentType: { type: String, enum: ['kick', 'ban', 'timeout'], default: 'kick' },
            timeoutDuration: { type: Number, default: 10 }
        },
        antiRoleCreate: { 
            enabled: { type: Boolean, default: false },
            limit: { type: Number, default: 2 },
            punishmentType: { type: String, enum: ['kick', 'ban', 'timeout'], default: 'ban' },
            timeoutDuration: { type: Number, default: 30 }
        },
        antiRoleDelete: { 
            enabled: { type: Boolean, default: false },
            limit: { type: Number, default: 2 },
            punishmentType: { type: String, enum: ['kick', 'ban', 'timeout'], default: 'ban' },
            timeoutDuration: { type: Number, default: 30 }
        },
        antiChannelCreate: { 
            enabled: { type: Boolean, default: false },
            limit: { type: Number, default: 3 },
            punishmentType: { type: String, enum: ['kick', 'ban', 'timeout'], default: 'ban' },
            timeoutDuration: { type: Number, default: 30 }
        },
        antiChannelDelete: { 
            enabled: { type: Boolean, default: false },
            limit: { type: Number, default: 3 },
            punishmentType: { type: String, enum: ['kick', 'ban', 'timeout'], default: 'ban' },
            timeoutDuration: { type: Number, default: 30 }
        },
        antiMention: { 
            enabled: { type: Boolean, default: false },
            limit: { type: Number, default: 5 },
            punishmentType: { type: String, enum: ['kick', 'ban', 'timeout'], default: 'timeout' },
            timeoutDuration: { type: Number, default: 5 }
        },
        antiBotAdd: { 
            enabled: { type: Boolean, default: false },
            limit: { type: Number, default: 1 },
            punishmentType: { type: String, enum: ['kick', 'ban', 'timeout'], default: 'ban' },
            timeoutDuration: { type: Number, default: 60 }
        },
        antiPrune: { 
            enabled: { type: Boolean, default: false },
            limit: { type: Number, default: 1 },
            punishmentType: { type: String, enum: ['kick', 'ban', 'timeout'], default: 'ban' },
            timeoutDuration: { type: Number, default: 60 }
        },
        antiDangerousRolePermUpdate: { 
            enabled: { type: Boolean, default: false },
            limit: { type: Number, default: 1 },
            punishmentType: { type: String, enum: ['kick', 'ban', 'timeout'], default: 'ban' },
            timeoutDuration: { type: Number, default: 60 }
        },
        antiDangerousRoleAdd: { 
            enabled: { type: Boolean, default: false },
            limit: { type: Number, default: 1 },
            punishmentType: { type: String, enum: ['kick', 'ban', 'timeout'], default: 'ban' },
            timeoutDuration: { type: Number, default: 60 }
        },
        antiServerRename: { 
            enabled: { type: Boolean, default: false },
            limit: { type: Number, default: 1 },
            punishmentType: { type: String, enum: ['kick', 'ban', 'timeout'], default: 'kick' },
            timeoutDuration: { type: Number, default: 30 }
        },
        antiVanityChange: { 
            enabled: { type: Boolean, default: false },
            limit: { type: Number, default: 1 },
            punishmentType: { type: String, enum: ['kick', 'ban', 'timeout'], default: 'ban' },
            timeoutDuration: { type: Number, default: 30 }
        },
        antiIconChange: { 
            enabled: { type: Boolean, default: false },
            limit: { type: Number, default: 1 },
            punishmentType: { type: String, enum: ['kick', 'ban', 'timeout'], default: 'kick' },
            timeoutDuration: { type: Number, default: 30 }
        },
        antiChannelRename: { 
            enabled: { type: Boolean, default: false },
            limit: { type: Number, default: 5 },
            punishmentType: { type: String, enum: ['kick', 'ban', 'timeout'], default: 'timeout' },
            timeoutDuration: { type: Number, default: 15 }
        },
        antiRoleRename: { 
            enabled: { type: Boolean, default: false },
            limit: { type: Number, default: 5 },
            punishmentType: { type: String, enum: ['kick', 'ban', 'timeout'], default: 'timeout' },
            timeoutDuration: { type: Number, default: 15 }
        },
        antiInviteLink: { 
            enabled: { type: Boolean, default: false },
            limit: { type: Number, default: 3 },
            punishmentType: { type: String, enum: ['kick', 'ban', 'timeout'], default: 'timeout' },
            timeoutDuration: { type: Number, default: 5 }
        },
        antiEmojiCreate: { 
            enabled: { type: Boolean, default: false },
            limit: { type: Number, default: 5 },
            punishmentType: { type: String, enum: ['kick', 'ban', 'timeout'], default: 'timeout' },
            timeoutDuration: { type: Number, default: 15 }
        },
        antiEmojiRename: { 
            enabled: { type: Boolean, default: false },
            limit: { type: Number, default: 10 },
            punishmentType: { type: String, enum: ['kick', 'ban', 'timeout'], default: 'timeout' },
            timeoutDuration: { type: Number, default: 10 }
        },
        antiEmojiDelete: { 
            enabled: { type: Boolean, default: false },
            limit: { type: Number, default: 5 },
            punishmentType: { type: String, enum: ['kick', 'ban', 'timeout'], default: 'ban' },
            timeoutDuration: { type: Number, default: 30 }
        },
        antiGhostPing: { 
            enabled: { type: Boolean, default: false },
            limit: { type: Number, default: 3 },
            punishmentType: { type: String, enum: ['kick', 'ban', 'timeout'], default: 'timeout' },
            timeoutDuration: { type: Number, default: 5 }
        },
        antiSpam: { 
            enabled: { type: Boolean, default: false },
            limit: { type: Number, default: 5 },
            punishmentType: { type: String, enum: ['kick', 'ban', 'timeout'], default: 'timeout' },
            timeoutDuration: { type: Number, default: 10 }
        },
        antiRaid: { 
            enabled: { type: Boolean, default: false },
            limit: { type: Number, default: 10 },
            punishmentType: { type: String, enum: ['kick', 'ban', 'timeout'], default: 'ban' },
            timeoutDuration: { type: Number, default: 60 }
        }
    },
    logChannels: {
        banLog: String,
        kickLog: String,
        roleLog: String,
        channelLog: String,
        generalLog: String,
        securityLog: String,
        messageLog: String,
        joinLeaveLog: String
    },
    verification: {
        enabled: { type: Boolean, default: false },
        channelId: String,
        roleId: String,
        message: { type: String, default: 'Clicca sul pulsante per verificarti!' },
        captchaEnabled: { type: Boolean, default: true },
        verificationMessageId: String,
        embedColor: { type: String, default: '#3498DB' }
    },
    whitelist: [String],
    blacklist: [String],
    antiRaidData: {
        joinCount: { type: Number, default: 0 },
        lastReset: { type: Date, default: Date.now }
    },
    userMessageCounts: Map,
    lastMessages: Map,
    userViolationCounts: {
        type: Map,
        default: new Map()
    }
});

const Guild = mongoose.model('Guild', guildSchema);

const actionCooldowns = new Map();
const userSpamCounts = new Map();
const recentJoins = new Map();
const userMentionCounts = new Map();

app.use(express.static('public'));
app.use(express.json());
app.use(session({
    secret: process.env.SESSION_SECRET || 'una_chiave_segreta_molto_lunga_e_casuale_per_le_sessioni',
    resave: false,
    saveUninitialized: false,
    store: MongoStore.create({
        mongoUrl: process.env.MONGODB_URI || 'mongodb://localhost:27017/securitybot'
    }),
    cookie: { maxAge: 24 * 60 * 60 * 1000 }
}));

app.use(passport.initialize());
app.use(passport.session());

passport.use(new DiscordStrategy({
    clientID: process.env.DISCORD_CLIENT_ID,
    clientSecret: process.env.DISCORD_CLIENT_SECRET,
    callbackURL: process.env.CALLBACK_URL,
    scope: ['identify', 'guilds']
}, (accessToken, refreshToken, profile, done) => {
    profile.accessToken = accessToken;
    return done(null, profile);
}));

passport.serializeUser((user, done) => done(null, user));
passport.deserializeUser((user, done) => done(null, user));

function isInCooldown(guildId, action, duration = 3000) {
    const key = `${guildId}_${action}`;
    const now = Date.now();
    
    if (actionCooldowns.has(key)) {
        const lastAction = actionCooldowns.get(key);
        if (now - lastAction < duration) {
            return true;
        }
    }
    
    actionCooldowns.set(key, now);
    return false;
}

async function logAction(guild, action, details, logType = 'generalLog', embed = null) {
    try {
        const guildData = await Guild.findOne({ guildId: guild.id });
        if (!guildData) {
            return;
        }
        if (!guildData.logChannels[logType]) {
            return;
        }

        const logChannel = guild.channels.cache.get(guildData.logChannels[logType]);
        if (!logChannel) {
            return;
        }

        if (!logChannel.permissionsFor(guild.members.me).has(PermissionsBitField.Flags.SendMessages)) {
            return;
        }

        const logEmbed = embed || new EmbedBuilder()
            .setTitle(`🛡️ Azione di Sicurezza: \${action}`)
            .setDescription(details)
            .setColor('#FF0000')
            .setTimestamp()
            .setFooter({ text: 'Sefion Security', iconURL: 'https://media.discordapp.net/attachments/1417150708704084122/1417567764331233401/azzurro-e-bianco.png' });

        await logChannel.send({ embeds: [logEmbed] });
    } catch (error) {
        console.error('[LogAction Error] Errore durante il logging:', error);
    }
}

async function hasPermission(guild, userId, action) {
    try {
        const guildData = await Guild.findOne({ guildId: guild.id });
        if (!guildData) {
            return false;
        }

        if (guildData.ownerId === userId) {
            return true;
        }
        
        if (guildData.whitelist.includes(userId)) {
            return true;
        }

        const member = guild.members.cache.get(userId);
        
        if (member && guildData.trustedRoles.length > 0) {
            const hasTrustedRole = guildData.trustedRoles.some(roleId => {
                return member.roles.cache.has(roleId);
            });
            
            if (hasTrustedRole) {
                return true;
            }
        }
        
        const moderator = guildData.moderators.find(mod => mod.userId === userId);
        
        if (!moderator) {
            return false;
        }

        const permissionMap = {
            'ban': 'manageBans',
            'kick': 'manageKicks',
            'role': 'manageRoles',
            'channel': 'manageChannels',
            'message': 'manageMessages',
            'settings': 'manageSettings'
        };

        const permKey = permissionMap[action];
        const hasSpecificPermission = moderator.permissions[permKey] || false;
        
        return hasSpecificPermission;
    } catch (error) {
        console.error('[HasPermission Error] Errore durante il controllo permessi:', error);
        return false;
    }
}

async function generateCaptcha() {
    const width = 200;
    const height = 100;
    const canvas = Canvas.createCanvas(width, height);
    const ctx = canvas.getContext('2d');

    ctx.fillStyle = '#f0f0f0';
    ctx.fillRect(0, 0, width, height);

    const captchaText = Math.random().toString(36).substring(2, 8).toUpperCase();
    
    ctx.fillStyle = '#333';
    ctx.font = 'bold 30px Arial';
    ctx.textAlign = 'center';
    ctx.fillText(captchaText, width / 2, height / 2 + 10);

    for (let i = 0; i < 5; i++) {
        ctx.strokeStyle = '#ccc';
        ctx.beginPath();
        ctx.moveTo(Math.random() * width, Math.random() * height);
        ctx.lineTo(Math.random() * width, Math.random() * height);
        ctx.stroke();
    }

    return { buffer: canvas.toBuffer(), text: captchaText };
}

async function sendAutoVerificationMessage(guild, guildData) {
    try {
        const verifyChannel = guild.channels.cache.get(guildData.verification.channelId);
        if (!verifyChannel) {
            return;
        }

        if (!verifyChannel.permissionsFor(guild.members.me).has([PermissionsBitField.Flags.SendMessages, PermissionsBitField.Flags.EmbedLinks])) {
            return;
        }

        if (guildData.verification.verificationMessageId) {
            try {
                const oldMessage = await verifyChannel.messages.fetch(guildData.verification.verificationMessageId);
                await oldMessage.delete();
            } catch (error) {
                console.warn(`[AutoVerification] Impossibile eliminare il vecchio messaggio di verifica: ${error.message}`);
            }
        }

        const embed = new EmbedBuilder()
            .setTitle('🔒 Verifica Richiesta')
            .setDescription(guildData.verification.message)
            .setColor(guildData.verification.embedColor)
            .setThumbnail('https://media.discordapp.net/attachments/1417150708704084122/1417567764331233401/azzurro-e-bianco.png')
            .setFooter({ text: 'Sefion Security - Clicca il pulsante sotto per verificarti', iconURL: guild.iconURL() });

        let components = [];
        let captchaAttachment = null;

        if (guildData.verification.captchaEnabled) {
            const captcha = await generateCaptcha();
            captchaAttachment = new AttachmentBuilder(captcha.buffer, { name: 'captcha.png' });
            
            embed.setImage('attachment://captcha.png');
            embed.addFields({ name: '🔤 Codice Captcha', value: 'Inserisci il codice mostrato nell\'immagine cliccando il pulsante', inline: false });
            
            const button = new ButtonBuilder()
                .setCustomId(`verify_captcha_${captcha.text}`)
                .setLabel('🔓 Inserisci Codice')
                .setStyle(ButtonStyle.Primary);
            
            components = [new ActionRowBuilder().addComponents(button)];
        } else {
            const button = new ButtonBuilder()
                .setCustomId(`verify_normal`)
                .setLabel('✅ Verificati')
                .setStyle(ButtonStyle.Success);
            
            components = [new ActionRowBuilder().addComponents(button)];
        }

        const messageOptions = {
            embeds: [embed],
            components: components
        };
        if (captchaAttachment) {
            messageOptions.files = [captchaAttachment];
        }

        const sentMessage = await verifyChannel.send(messageOptions);
        
        guildData.verification.verificationMessageId = sentMessage.id;
        await guildData.save();
    } catch (error) {
        console.error('[AutoVerification Error] Errore durante l\'invio automatico del messaggio di verifica:', error);
    }
}

async function trackViolation(guild, userId, violationType, guildData) {
    const key = `${userId}_${violationType}`;
    const violations = guildData.userViolationCounts.get(key) || 0;
    const newViolations = violations + 1;
    
    guildData.userViolationCounts.set(key, newViolations);
    await guildData.save();
    
    return newViolations;
}

async function applyPunishment(guild, userId, punishmentType, duration, reason) {
    const member = guild.members.cache.get(userId);
    
    if (!member) {
        return { success: false, reason: 'Utente non trovato nel server' };
    }
    
    try {
        switch (punishmentType) {
            case 'kick':
                if (member.kickable && guild.members.me.permissions.has(PermissionsBitField.Flags.KickMembers)) {
                    await member.kick(`Sefion Security: ${reason}`);
                    return { success: true, action: 'kickato' };
                } else {
                    return { success: false, reason: 'Impossibile kickare l\'utente (permessi insufficienti o ruolo superiore)' };
                }
                break;
            case 'ban':
                if (member.bannable && guild.members.me.permissions.has(PermissionsBitField.Flags.BanMembers)) {
                    await member.ban({ reason: `Sefion Security: ${reason}` });
                    return { success: true, action: 'bannato' };
                } else {
                    return { success: false, reason: 'Impossibile bannare l\'utente (permessi insufficienti o ruolo superiore)' };
                }
                break;
            case 'timeout':
                if (guild.members.me.permissions.has(PermissionsBitField.Flags.ModerateMembers) && member.moderatable) {
                    await member.timeout(duration * 60 * 1000, `Sefion Security: ${reason}`);
                    return { success: true, action: `messo in timeout per ${duration} minuti` };
                } else {
                    return { success: false, reason: 'Impossibile mettere in timeout l\'utente (permessi insufficienti o ruolo superiore)' };
                }
                break;
        }
    } catch (error) {
        console.error(`[ApplyPunishment] Errore applicando punizione ${punishmentType} a ${userId}:`, error);
        return { success: false, reason: `Errore durante l'applicazione della punizione: ${error.message}` };
    }
    
    return { success: false, reason: 'Tipo di punizione non riconosciuto' };
}

async function checkAndPunish(guild, userId, action, guildData) {
    if (await hasPermission(guild, userId, action)) {
        return { punished: false, reason: 'Utente autorizzato' };
    }
    
    const setting = guildData.settings[action];
    if (!setting || !setting.enabled) {
        return { punished: false, reason: 'Protezione disabilitata' };
    }
    
    const violations = await trackViolation(guild, userId, action, guildData);
    
    if (violations >= setting.limit) {
        const punishment = await applyPunishment(
            guild, 
            userId, 
            setting.punishmentType, 
            setting.timeoutDuration, 
            `Limite violazioni ${action} raggiunto (${violations}/${setting.limit})`
        );
        
        if (punishment.success) {
            const key = `${userId}_${action}`;
            guildData.userViolationCounts.delete(key);
            await guildData.save();
            return { punished: true, action: punishment.action, violations, limit: setting.limit };
        } else {
            return { punished: false, reason: punishment.reason, violations, limit: setting.limit };
        }
    }
    
    return { punished: false, reason: 'Limite non raggiunto', violations, limit: setting.limit };
}

client.on('ready', async () => {
    console.log(`Bot Discord: ${client.user.tag} è online!`);
    
    client.guilds.cache.forEach(async guild => {
        let guildData = await Guild.findOne({ guildId: guild.id });
        if (!guildData) {
            guildData = await new Guild({
                guildId: guild.id,
                ownerId: guild.ownerId
            }).save();
        } else if (guildData.ownerId !== guild.ownerId) {
            guildData.ownerId = guild.ownerId;
            await guildData.save();
        }
    });
    
    setInterval(() => {
        const now = Date.now();
        const timeWindow = 10000;
        
        for (const [userId, userData] of userMentionCounts.entries()) {
            userData.mentions = userData.mentions.filter(timestamp => now - timestamp < timeWindow);
            
            if (userData.mentions.length === 0) {
                userMentionCounts.delete(userId);
            }
        }
        
        recentJoins.clear();
    }, 30000);
});

client.on('guildCreate', async guild => {
    await new Guild({
        guildId: guild.id,
        ownerId: guild.ownerId
    }).save();

    try {
        const owner = await guild.fetchOwner();
        const embed = new EmbedBuilder()
            .setTitle('🛡️ Benvenuto in Sefion Security!')
            .setDescription(`Ciao ${owner.user.username}!\n\nGrazie per aver aggiunto Sefion Security Bot al tuo server **${guild.name}**.\n\n🌐 **Dashboard**: Configura il bot su ${process.env.CALLBACK_URL.replace('/auth/discord/callback', '') || 'http://localhost:3000'}\n🔧 **Comandi**: Usa \`/help\` per vedere tutti i comandi\n📞 **Supporto**: Entra nel nostro server di supporto\n\n**Configurazione Rapida:**\n1. Vai su ${process.env.CALLBACK_URL.replace('/auth/discord/callback', '') || 'http://localhost:3000'} e accedi con Discord\n2. Seleziona il tuo server\n3. Configura le protezioni desiderate\n4. Imposta i canali di log\n5. Aggiungi moderatori se necessario`)
            .setColor('#00FF00')
            .setThumbnail('https://media.discordapp.net/attachments/1417150708704084122/1417567764331233401/azzurro-e-bianco.png')
            .addFields(
                { name: '🆓 Versione Gratuita', value: 'Anti-nuke base, gestione moderatori, log personalizzati', inline: true },
                { name: '⭐ Versione Plus', value: 'Tutto il Free + Anti-spam, Anti-emoji, Anti-ghost ping', inline: true },
                { name: '💎 Versione Premium', value: 'Tutto il Plus + Anti-raid avanzato, Priorità supporto', inline: true }
            )
            .setFooter({ text: 'Sefion Security Bot - Protezione Discord', iconURL: 'https://media.discordapp.net/attachments/1417150708704084122/1417567764331233401/azzurro-e-bianco.png' });

        await owner.send({ embeds: [embed] });
    } catch (error) {
        console.error('[GuildCreate Error] Impossibile inviare messaggio al proprietario:', error);
    }

    await logAction(guild, 'Bot Aggiunto', `Sefion Security Bot è stato aggiunto al server **${guild.name}** (${guild.id})`, 'securityLog');
});

client.on('guildBanAdd', async ban => {
    if (isInCooldown(ban.guild.id, 'ban')) return;

    const guildData = await Guild.findOne({ guildId: ban.guild.id });
    if (!guildData || !guildData.settings.antiBan?.enabled) {
        return;
    }

    try {
        const auditLogs = await ban.guild.fetchAuditLogs({
            type: AuditLogEvent.MemberBanAdd,
            limit: 1
        });

        const banLog = auditLogs.entries.first();
        if (!banLog || Date.now() - banLog.createdTimestamp > 5000) {
            return;
        }

        const { executor, target } = banLog;
        
        if (executor.id === client.user.id) {
            return;
        }

        const result = await checkAndPunish(ban.guild, executor.id, 'antiBan', guildData);
        
        let reverted = false;
        if (!await hasPermission(ban.guild, executor.id, 'ban')) {
            if (ban.guild.members.me.permissions.has(PermissionsBitField.Flags.BanMembers)) {
                try {
                    await ban.guild.members.unban(target.id, 'Anti-Ban: Azione revertita');
                    reverted = true;
                } catch (error) {
                    console.error('Errore nel revertire il ban:', error);
                }
            }
        }
        
        const embed = new EmbedBuilder()
            .setTitle('🚫 Anti-Ban Attivato')
            .setDescription(
                result.punished 
                    ? `❌ **Utente ${result.action}** per aver raggiunto il limite di violazioni!`
                    : reverted 
                        ? `⚠️ **Ban revertito** - Azione non autorizzata rilevata`
                        : `⚠️ **Tentativo di ban rilevato** - Violazione registrata`
            )
            .addFields(
                { name: '👤 Esecutore', value: `${executor.tag}\n\`${executor.id}\``, inline: true },
                { name: '🎯 Vittima', value: `${target.tag}\n\`${target.id}\``, inline: true },
                { name: '📊 Violazioni', value: `**${result.violations || 0}/${result.limit || guildData.settings.antiBan.limit}**`, inline: true },
                                { name: '⚖️ Azione Presa', value: 
                    result.punished 
                        ? `✅ Utente ${result.action}`
                        : reverted 
                            ? `🔄 Ban revertito`
                            : `📝 Violazione registrata`, 
                    inline: true },
                { name: '🛡️ Stato Protezione', value: `${guildData.settings.antiBan.enabled ? '🟢 Attiva' : '🔴 Disattiva'}`, inline: true },
                { name: '⚙️ Punizione Configurata', value: `${guildData.settings.antiBan.punishmentType.toUpperCase()}`, inline: true }
            )
            .setColor(result.punished ? '#FF0000' : reverted ? '#FF6600' : '#FFFF00')
            .setTimestamp()
            .setFooter({ 
                text: 'Sefion Security - Sistema Anti-Ban', 
                iconURL: 'https://media.discordapp.net/attachments/1417150708704084122/1417567764331233401/azzurro-e-bianco.png' 
            });

        if (!result.punished && result.reason && result.reason !== 'Limite non raggiunto') {
            embed.addFields({ 
                name: '⚠️ Motivo Mancata Punizione', 
                value: result.reason,
                inline: false 
            });
        }

        await logAction(ban.guild, 'Anti-Ban', '', 'securityLog', embed);
    } catch (error) {
        console.error('Errore anti-ban:', error);
    }
});

client.on('guildMemberRemove', async member => {
    if (isInCooldown(member.guild.id, 'kick')) return;

    const guildData = await Guild.findOne({ guildId: member.guild.id });
    if (!guildData) {
        const leaveEmbed = new EmbedBuilder()
            .setTitle('👋 Membro Uscito')
            .setDescription(`${member.user.tag} ha lasciato il server`)
            .setThumbnail(member.user.displayAvatarURL())
            .addFields(
                { name: '👤 Utente', value: `${member.user.tag}\n\`${member.id}\``, inline: true },
                { name: '📅 Entrato il', value: `<t:${Math.floor(member.joinedTimestamp / 1000)}:R>`, inline: true },
                { name: '📊 Account Creato', value: `<t:${Math.floor(member.user.createdTimestamp / 1000)}:R>`, inline: true }
            )
            .setColor('#E74C3C')
            .setTimestamp()
            .setFooter({ text: 'Sefion Security', iconURL: 'https://media.discordapp.net/attachments/1417150708704084122/1417567764331233401/azzurro-e-bianco.png' });
        await logAction(member.guild, 'Membro Rimosso', '', 'joinLeaveLog', leaveEmbed);
        return;
    }

    try {
        await new Promise(resolve => setTimeout(resolve, 1000));

        const auditLogs = await member.guild.fetchAuditLogs({
            type: AuditLogEvent.MemberKick,
            limit: 1
        });

        const kickLog = auditLogs.entries.first();
        if (kickLog && kickLog.target.id === member.id && Date.now() - kickLog.createdTimestamp <= 5000) {
            const { executor } = kickLog;
            
            if (executor.id !== client.user.id && guildData.settings.antiKick?.enabled) {
                const result = await checkAndPunish(member.guild, executor.id, 'antiKick', guildData);
                
                const embed = new EmbedBuilder()
                    .setTitle('👢 Anti-Kick Attivato')
                    .setDescription(
                        result.punished 
                            ? `❌ **Utente ${result.action}** per aver raggiunto il limite di violazioni!`
                            : `⚠️ **Tentativo di kick rilevato** - Violazione registrata`
                    )
                    .addFields(
                        { name: '👤 Esecutore', value: `${executor.tag}\n\`${executor.id}\``, inline: true },
                        { name: '🎯 Vittima', value: `${member.user.tag}\n\`${member.id}\``, inline: true },
                        { name: '📊 Violazioni', value: `**${result.violations || 0}/${result.limit || guildData.settings.antiKick.limit}**`, inline: true },
                        { name: '⚖️ Azione Presa', value: 
                            result.punished 
                                ? `✅ Utente ${result.action}`
                                : `📝 Violazione registrata`, 
                            inline: true },
                        { name: '🛡️ Stato Protezione', value: `${guildData.settings.antiKick.enabled ? '🟢 Attiva' : '🔴 Disattiva'}`, inline: true },
                        { name: '⚙️ Punizione Configurata', value: `${guildData.settings.antiKick.punishmentType.toUpperCase()}`, inline: true }
                    )
                    .setColor(result.punished ? '#FF0000' : '#FFFF00')
                    .setTimestamp()
                    .setFooter({ 
                        text: 'Sefion Security - Sistema Anti-Kick', 
                        iconURL: 'https://media.discordapp.net/attachments/1417150708704084122/1417567764331233401/azzurro-e-bianco.png' 
                    });

                if (!result.punished && result.reason && result.reason !== 'Limite non raggiunto') {
                    embed.addFields({ 
                        name: '⚠️ Motivo Mancata Punizione', 
                        value: result.reason,
                        inline: false 
                    });
                }

                await logAction(member.guild, 'Anti-Kick', '', 'securityLog', embed);
            }
        }
    } catch (error) {
        console.error('Errore anti-kick:', error);
    }

    const leaveEmbed = new EmbedBuilder()
        .setTitle('👋 Membro Uscito')
        .setDescription(`${member.user.tag} ha lasciato il server`)
        .setThumbnail(member.user.displayAvatarURL())
        .addFields(
            { name: '👤 Utente', value: `${member.user.tag}\n\`${member.id}\``, inline: true },
            { name: '📅 Entrato il', value: `<t:${Math.floor(member.joinedTimestamp / 1000)}:R>`, inline: true },
            { name: '📊 Account Creato', value: `<t:${Math.floor(member.user.createdTimestamp / 1000)}:R>`, inline: true }
        )
        .setColor('#E74C3C')
        .setTimestamp()
        .setFooter({ text: 'Sefion Security', iconURL: 'https://media.discordapp.net/attachments/1417150708704084122/1417567764331233401/azzurro-e-bianco.png' });

    await logAction(member.guild, 'Membro Rimosso', '', 'joinLeaveLog', leaveEmbed);
});

client.on('roleCreate', async role => {
    if (isInCooldown(role.guild.id, 'roleCreate')) return;

    const guildData = await Guild.findOne({ guildId: role.guild.id });
    if (!guildData || !guildData.settings.antiRoleCreate?.enabled) {
        return;
    }

    try {
        const auditLogs = await role.guild.fetchAuditLogs({
            type: AuditLogEvent.RoleCreate,
            limit: 1
        });

        const roleLog = auditLogs.entries.first();
        if (!roleLog || Date.now() - roleLog.createdTimestamp > 5000) {
            return;
        }

        const { executor } = roleLog;
        
        if (executor.id === client.user.id) {
            return;
        }

        const result = await checkAndPunish(role.guild, executor.id, 'antiRoleCreate', guildData);
        
        let deleted = false;
        if (!await hasPermission(role.guild, executor.id, 'role')) {
            if (role.guild.members.me.permissions.has(PermissionsBitField.Flags.ManageRoles) && role.editable) {
                try {
                    await role.delete('Sefion Security: Creazione ruolo non autorizzata');
                    deleted = true;
                } catch (error) {
                    console.error('Errore nell\'eliminare il ruolo:', error);
                }
            }
        }
        
        const embed = new EmbedBuilder()
            .setTitle('🎭 Anti-Role Create Attivato')
            .setDescription(
                result.punished 
                    ? `❌ **Utente ${result.action}** per aver raggiunto il limite di violazioni!`
                    : deleted 
                        ? `⚠️ **Ruolo eliminato** - Creazione non autorizzata rilevata`
                        : `⚠️ **Tentativo di creazione ruolo rilevato** - Violazione registrata`
            )
            .addFields(
                { name: '👤 Esecutore', value: `${executor.tag}\n\`${executor.id}\``, inline: true },
                { name: '🎭 Ruolo', value: deleted ? `${role.name}\n\`${role.id}\`` : `${role.name}\n\`${role.id}\``, inline: true },
                { name: '📊 Violazioni', value: `**${result.violations || 0}/${result.limit || guildData.settings.antiRoleCreate.limit}**`, inline: true },
                { name: '⚖️ Azione Presa', value: 
                    result.punished 
                        ? `✅ Utente ${result.action}`
                        : deleted 
                            ? `🗑️ Ruolo eliminato`
                            : `📝 Violazione registrata`, 
                    inline: true },
                { name: '🛡️ Stato Protezione', value: `${guildData.settings.antiRoleCreate.enabled ? '🟢 Attiva' : '🔴 Disattiva'}`, inline: true },
                { name: '⚙️ Punizione Configurata', value: `${guildData.settings.antiRoleCreate.punishmentType.toUpperCase()}`, inline: true }
            )
            .setColor(result.punished ? '#FF0000' : deleted ? '#FF6600' : '#FFFF00')
            .setTimestamp()
            .setFooter({ 
                text: 'Sefion Security - Sistema Anti-Role Create', 
                iconURL: 'https://media.discordapp.net/attachments/1417150708704084122/1417567764331233401/azzurro-e-bianco.png' 
            });

        if (!result.punished && result.reason && result.reason !== 'Limite non raggiunto') {
            embed.addFields({ 
                name: '⚠️ Motivo Mancata Punizione', 
                value: result.reason,
                inline: false 
            });
        }

        await logAction(role.guild, 'Anti-Role Create', '', 'securityLog', embed);
    } catch (error) {
        console.error('Errore anti-role create:', error);
    }
});

client.on('messageCreate', async message => {
    if (message.author.bot || !message.guild) return;

    const guildData = await Guild.findOne({ guildId: message.guild.id });
    if (!guildData) {
        return;
    }

    if (guildData.settings.antiMention?.enabled && message.mentions.users.size > 0) {
        const userId = message.author.id;
        const now = Date.now();
        const timeWindow = 10000;
        
        if (!userMentionCounts.has(userId)) {
            userMentionCounts.set(userId, { mentions: [], lastReset: now });
        }
        
        const userData = userMentionCounts.get(userId);
        
        userData.mentions = userData.mentions.filter(timestamp => now - timestamp < timeWindow);
        
        for (let i = 0; i < message.mentions.users.size; i++) {
            userData.mentions.push(now);
        }
        
        const totalMentions = userData.mentions.length;
        
        if (totalMentions >= guildData.settings.antiMention.limit) {
            
            if (!(await hasPermission(message.guild, message.author.id, 'message'))) {
                try {
                    if (!message.guild.members.me.permissions.has(PermissionsBitField.Flags.ManageMessages)) {
                        return;
                    }

                    try {
                        await message.delete();
                    } catch (deleteError) {
                        console.error('[Anti-Mention] Errore eliminazione messaggio:', deleteError);
                    }

                    userMentionCounts.delete(userId);

                    const result = await checkAndPunish(message.guild, message.author.id, 'antiMention', guildData);

                    if (!result.punished) {
                        const member = message.guild.members.cache.get(message.author.id);
                        if (member && member.moderatable && message.guild.members.me.permissions.has(PermissionsBitField.Flags.ModerateMembers)) {
                            try {
                                const timeoutDuration = guildData.settings.antiMention.timeoutDuration * 60 * 1000;
                                await member.timeout(timeoutDuration, `Sefion Security: Troppi mention in poco tempo (${totalMentions})`);
                            } catch (timeoutError) {
                                console.error('[Anti-Mention] Errore timeout temporaneo:', timeoutError);
                            }
                        }
                    }

                    const embed = new EmbedBuilder()
                        .setTitle('📢 Anti-Mention Attivato')
                        .setDescription(
                            result.punished 
                                ? `❌ **Utente ${result.action}** per aver raggiunto il limite di violazioni!`
                                : `⚠️ **Troppi mention in poco tempo** - Timeout applicato`
                        )
                        .addFields(
                            { name: '👤 Utente', value: `${message.author.tag}\n\`${message.author.id}\``, inline: true },
                            { name: '📢 Mention (10s)', value: `${totalMentions}`, inline: true },
                            { name: '🎯 Limite', value: `${guildData.settings.antiMention.limit}`, inline: true },
                            { name: '📊 Violazioni Sistema', value: `**${result.violations || 1}/${result.limit || guildData.settings.antiMention.limit}**`, inline: true },
                            { name: '⚖️ Azione', value: 
                                result.punished 
                                    ? `✅ ${result.action}`
                                    : `🗑️ Messaggio eliminato\n🔇 Timeout ${guildData.settings.antiMention.timeoutDuration} minuti`, 
                                inline: true },
                            { name: '⏱️ Finestra Temporale', value: '10 secondi', inline: true }
                        )
                        .setColor(result.punished ? '#FF0000' : '#FF6600')
                        .setTimestamp()
                        .setFooter({ 
                            text: 'Sefion Security - Anti-Mention Cumulativo', 
                            iconURL: 'https://media.discordapp.net/attachments/1417150708704084122/1417567764331233401/azzurro-e-bianco.png' 
                        });

                    await logAction(message.guild, 'Anti-Mention', '', 'messageLog', embed);

                    try {
                        const warningMsg = await message.channel.send({
                            content: `⚠️ ${message.author}, hai fatto troppi mention in poco tempo (${totalMentions}/${guildData.settings.antiMention.limit} in 10s).`,
                        });
                        
                        setTimeout(() => {
                            warningMsg.delete().catch(() => {});
                        }, 5000);
                    } catch (warningError) {
                        console.error('[Anti-Mention] Errore invio messaggio di avviso:', warningError);
                    }

                } catch (error) {
                    console.error('[Anti-Mention] Errore generale:', error);
                }
            }
        }
    }

    if (guildData.botType !== 'free' && guildData.settings.antiSpam?.enabled) {
        const userId = message.author.id;
        const now = Date.now();
        
        if (!userSpamCounts.has(userId)) {
            userSpamCounts.set(userId, { count: 1, lastMessage: now });
        } else {
            const userData = userSpamCounts.get(userId);
            if (now - userData.lastMessage < 5000) {
                userData.count++;
                userData.lastMessage = now;
                
                if (userData.count >= guildData.settings.antiSpam.limit) {
                    if (!(await hasPermission(message.guild, message.author.id, 'message'))) {
                        try {
                            const result = await checkAndPunish(message.guild, message.author.id, 'antiSpam', guildData);
                            
                            if (!result.punished && message.guild.members.me.permissions.has(PermissionsBitField.Flags.ModerateMembers)) {
                                const member = message.guild.members.cache.get(userId);
                                if (member) {
                                    const timeoutDuration = guildData.settings.antiSpam.timeoutDuration * 60 * 1000;
                                    await member.timeout(timeoutDuration, 'Spam rilevato dal Sefion Security Bot');
                                }
                            }
                            
                            const embed = new EmbedBuilder()
                                .setTitle('🚫 Anti-Spam Attivato')
                                .setDescription(
                                    result.punished 
                                        ? `❌ **Utente ${result.action}** per aver raggiunto il limite di violazioni!`
                                        : `⚠️ **Spam rilevato e utente mutato** - Violazione registrata`
                                )
                                .addFields(
                                    { name: '👤 Utente', value: `${message.author.tag}\n\`${message.author.id}\``, inline: true },
                                    { name: '📨 Messaggi', value: `${userData.count} in 5 secondi`, inline: true },
                                    { name: '📊 Violazioni', value: `**${result.violations || 0}/${result.limit || guildData.settings.antiSpam.limit}**`, inline: true },
                                    { name: '⚖️ Azione Presa', value: 
                                        result.punished 
                                            ? `✅ Utente ${result.action}`
                                            : `🔇 Timeout ${guildData.settings.antiSpam.timeoutDuration} minuti`, 
                                        inline: true },
                                    { name: '🛡️ Stato Protezione', value: `${guildData.settings.antiSpam.enabled ? '🟢 Attiva' : '🔴 Disattiva'}`, inline: true },
                                    { name: '⚙️ Punizione Configurata', value: `${guildData.settings.antiSpam.punishmentType.toUpperCase()}`, inline: true }
                                )
                                .setColor(result.punished ? '#FF0000' : '#FF6600')
                                .setTimestamp()
                                .setFooter({ 
                                    text: 'Sefion Security - Sistema Anti-Spam', 
                                    iconURL: 'https://media.discordapp.net/attachments/1417150708704084122/1417567764331233401/azzurro-e-bianco.png' 
                                });

                            if (!result.punished && result.reason && result.reason !== 'Limite non raggiunto') {
                                embed.addFields({ 
                                    name: '⚠️ Motivo Mancata Punizione', 
                                    value: result.reason,
                                    inline: false 
                                });
                            }

                            await logAction(message.guild, 'Anti-Spam', '', 'messageLog', embed);
                            userSpamCounts.delete(userId);
                        } catch (error) {
                            console.error('Errore anti-spam:', error);
                        }
                    }
                }
            } else {
                userSpamCounts.set(userId, { count: 1, lastMessage: now });
            }
        }
    }

    if (guildData.settings.antiInviteLink?.enabled && (message.content.includes('discord.gg/') || message.content.includes('discord.com/invite/'))) {
        if (!(await hasPermission(message.guild, message.author.id, 'message'))) {
            try {
                if (!message.guild.members.me.permissions.has(PermissionsBitField.Flags.ManageMessages)) {
                    return;
                }

                await message.delete();

                const result = await checkAndPunish(message.guild, message.author.id, 'antiInviteLink', guildData);

                if (!result.punished) {
                    const member = message.guild.members.cache.get(message.author.id);
                    if (member && message.guild.members.me.permissions.has(PermissionsBitField.Flags.ModerateMembers)) {
                        const timeoutDuration = guildData.settings.antiInviteLink.timeoutDuration * 60 * 1000;
                        await member.timeout(timeoutDuration, 'Link di invito non autorizzato');
                    }
                }

                const embed = new EmbedBuilder()
                    .setTitle('🔗 Anti-Invite Link Attivato')
                    .setDescription(
                        result.punished 
                            ? `❌ **Utente ${result.action}** per aver raggiunto il limite di violazioni!`
                            : `⚠️ **Link di invito Discord rimosso** - Violazione registrata`
                    )
                    .addFields(
                        { name: '👤 Utente', value: `${message.author.tag}\n\`${message.author.id}\``, inline: true },
                        { name: '🔗 Contenuto', value: 'Link di invito Discord', inline: true },
                        { name: '📊 Violazioni', value: `**${result.violations || 0}/${result.limit || guildData.settings.antiInviteLink.limit}**`, inline: true },
                        { name: '⚖️ Azione Presa', value: 
                            result.punished 
                                ? `✅ Utente ${result.action}`
                                : `🗑️ Messaggio eliminato`, 
                            inline: true },
                        { name: '🛡️ Stato Protezione', value: `${guildData.settings.antiInviteLink.enabled ? '🟢 Attiva' : '🔴 Disattiva'}`, inline: true },
                        { name: '⚙️ Punizione Configurata', value: `${guildData.settings.antiInviteLink.punishmentType.toUpperCase()}`, inline: true }
                    )
                    .setColor(result.punished ? '#FF0000' : '#FF6600')
                    .setTimestamp()
                    .setFooter({ 
                        text: 'Sefion Security - Sistema Anti-Invite Link', 
                        iconURL: 'https://media.discordapp.net/attachments/1417150708704084122/1417567764331233401/azzurro-e-bianco.png' 
                    });

                if (!result.punished && result.reason && result.reason !== 'Limite non raggiunto') {
                    embed.addFields({ 
                        name: '⚠️ Motivo Mancata Punizione', 
                        value: result.reason,
                        inline: false 
                    });
                }

                await logAction(message.guild, 'Anti-Invite Link', '', 'messageLog', embed);
            } catch (error) {
                console.error('Errore anti-invite link:', error);
            }
        }
    }
});

client.on('interactionCreate', async interaction => {
    if (!interaction.isButton()) return;

    if (interaction.customId.startsWith('verify_')) {
        const parts = interaction.customId.split('_');
        
        if (parts[1] === 'captcha') {
            const correctCode = parts[2];
            
            const modal = new ModalBuilder()
                .setCustomId(`captcha_modal_${interaction.user.id}_${correctCode}`)
                .setTitle('Verifica Captcha');

            const captchaInput = new TextInputBuilder()
                .setCustomId('captcha_code')
                .setLabel('Inserisci il codice dal captcha')
                .setStyle(TextInputStyle.Short)
                .setMaxLength(6)
                .setRequired(true);

            const firstActionRow = new ActionRowBuilder().addComponents(captchaInput);
            modal.addComponents(firstActionRow);

            await interaction.showModal(modal);
            return;
        }

        if (parts[1] === 'normal') {
            const guildData = await Guild.findOne({ guildId: interaction.guild.id });
            if (!guildData || !guildData.verification.enabled) {
                return interaction.reply({ content: '❌ Verifica non configurata!', ephemeral: true });
            }

            try {
                const member = interaction.guild.members.cache.get(interaction.user.id);
                const role = interaction.guild.roles.cache.get(guildData.verification.roleId);
                
                if (!interaction.guild.members.me.permissions.has(PermissionsBitField.Flags.ManageRoles)) {
                    return interaction.reply({ content: '❌ Il bot non ha i permessi per assegnare ruoli!', ephemeral: true });
                }
                
                if (role && member) {
                    if (member.roles.cache.has(role.id)) {
                        return interaction.reply({ content: '✅ Sei già verificato!', ephemeral: true });
                    }

                    await member.roles.add(role);
                    await interaction.reply({ content: '✅ Verificato con successo!', ephemeral: true });
                    
                    const embed = new EmbedBuilder()
                        .setTitle('Utente Verificato')
                        .setDescription('Un utente si è verificato con successo.')
                        .addFields(
                            { name: 'Utente', value: `${member.user.tag} (${member.id})`, inline: true },
                            { name: 'Ruolo Assegnato', value: role.name, inline: true }
                        )
                        .setColor('#2ECC71')
                        .setTimestamp()
                        .setFooter({ text: 'Sefion Security', iconURL: 'https://media.discordapp.net/attachments/1417150708704084122/1417567764331233401/azzurro-e-bianco.png' });

                    await logAction(interaction.guild, 'Utente Verificato', '', 'generalLog', embed);
                } else {
                    await interaction.reply({ content: '❌ Errore durante la verifica! Ruolo non trovato.', ephemeral: true });
                }
            } catch (error) {
                console.error('Errore verifica:', error);
                await interaction.reply({ content: '❌ Errore durante la verifica!', ephemeral: true });
            }
        }
    }
});

client.on('interactionCreate', async interaction => {
    if (!interaction.isModalSubmit()) return;

    if (interaction.customId.startsWith('captcha_modal_')) {
        const parts = interaction.customId.split('_');
        const userId = parts[2];
        const correctCode = parts[3];
        const userCode = interaction.fields.getTextInputValue('captcha_code').toUpperCase();

        if (userCode !== correctCode) {
            return interaction.reply({ content: '❌ Codice captcha errato! Riprova.', ephemeral: true });
        }

        const guildData = await Guild.findOne({ guildId: interaction.guild.id });
        if (!guildData || !guildData.verification.enabled) {
            return interaction.reply({ content: '❌ Verifica non configurata!', ephemeral: true });
        }

        try {
            const member = interaction.guild.members.cache.get(userId);
            const role = interaction.guild.roles.cache.get(guildData.verification.roleId);
            
            if (!interaction.guild.members.me.permissions.has(PermissionsBitField.Flags.ManageRoles)) {
                return interaction.reply({ content: '❌ Il bot non ha i permessi per assegnare ruoli!', ephemeral: true });
            }
            
            if (role && member) {
                if (member.roles.cache.has(role.id)) {
                    return interaction.reply({ content: '✅ Sei già verificato!', ephemeral: true });
                }

                await member.roles.add(role);
                await interaction.reply({ content: '✅ Captcha completato! Sei stato verificato con successo!', ephemeral: true });
                
                const embed = new EmbedBuilder()
                    .setTitle('Utente Verificato (Captcha)')
                    .setDescription('Un utente ha completato la verifica captcha.')
                    .addFields(
                        { name: 'Utente', value: `${member.user.tag} (${member.id})`, inline: true },
                        { name: 'Ruolo Assegnato', value: role.name, inline: true },
                        { name: 'Metodo', value: 'Captcha', inline: true }
                    )
                    .setColor('#2ECC71')
                    .setTimestamp()
                    .setFooter({ text: 'Sefion Security', iconURL: 'https://media.discordapp.net/attachments/1417150708704084122/1417567764331233401/azzurro-e-bianco.png' });

                await logAction(interaction.guild, 'Utente Verificato', '', 'generalLog', embed);
            }
        } catch (error) {
            console.error('Errore verifica captcha:', error);
            await interaction.reply({ content: '❌ Errore durante la verifica!', ephemeral: true });
        }
    }
});

app.post('/api/punishment-settings', async (req, res) => {
    if (!req.isAuthenticated()) return res.status(401).json({ error: 'Non autorizzato' });
    
    const { guildId, setting, config } = req.body;
    
    try {
        const updateQuery = {};
        updateQuery[`settings.${setting}.enabled`] = config.enabled;
        updateQuery[`settings.${setting}.limit`] = config.limit;
        updateQuery[`settings.${setting}.punishmentType`] = config.punishmentType;
        updateQuery[`settings.${setting}.timeoutDuration`] = config.timeoutDuration;
            
        await Guild.findOneAndUpdate(
            { guildId },
            { $set: updateQuery },
            { upsert: true }
        );
        
        res.json({ success: true });
    } catch (error) {
        console.error('Errore salvataggio configurazione punizione:', error);
        res.status(500).json({ error: 'Errore del server' });
    }
});

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.get('/auth/discord', passport.authenticate('discord'));

app.get('/auth/discord/callback', 
    passport.authenticate('discord', { failureRedirect: '/' }),
    (req, res) => {
        res.redirect('/dashboard');
    }
);

app.get('/dashboard', (req, res) => {
    if (!req.isAuthenticated()) {
        return res.redirect('/auth/discord');
    }
    res.sendFile(path.join(__dirname, 'public', 'dashboard.html'));
});

app.get('/api/user', (req, res) => {
    if (!req.isAuthenticated()) {
        return res.status(401).json({ error: 'Non autorizzato' });
    }
    res.json({
        id: req.user.id,
        username: req.user.username,
        avatar: req.user.avatar
    });
});

app.get('/api/user/guilds', async (req, res) => {
    if (!req.isAuthenticated()) {
        return res.status(401).json({ error: 'Non autorizzato' });
    }

    const userGuilds = req.user.guilds;

    const filteredGuilds = userGuilds.filter(userGuild => {
        const userPermissions = new PermissionsBitField(BigInt(userGuild.permissions));
        return userPermissions.has(PermissionsBitField.Flags.Administrator) || 
               userPermissions.has(PermissionsBitField.Flags.ManageGuild) ||
               userGuild.owner;
    });

    const guildsWithBotStatus = filteredGuilds.map(userGuild => {
        const botGuild = client.guilds.cache.get(userGuild.id);
        const botInGuild = !!botGuild;

        const userPermissions = new PermissionsBitField(BigInt(userGuild.permissions));
        const userIsAdminOrManageGuildOrOwner = userPermissions.has(PermissionsBitField.Flags.Administrator) || 
                                               userPermissions.has(PermissionsBitField.Flags.ManageGuild) ||
                                               userGuild.owner;

        return {
            id: userGuild.id,
            name: userGuild.name,
            icon: userGuild.icon,
            owner: userGuild.owner,
            permissions: userGuild.permissions,
            botInGuild: botInGuild,
            userCanManage: userIsAdminOrManageGuildOrOwner
        };
    });
    
    res.json(guildsWithBotStatus);
});

app.get('/api/guild/:guildId/channels', async (req, res) => {
    if (!req.isAuthenticated()) return res.status(401).json({ error: 'Non autorizzato' });
    
    const { guildId } = req.params;
    const guild = client.guilds.cache.get(guildId);
    
    if (!guild) {
        return res.status(404).json({ error: 'Server non trovato' });
    }
    
    const channels = guild.channels.cache
        .filter(channel => channel.type === ChannelType.GuildText)
        .map(channel => ({
            id: channel.id,
            name: channel.name,
            type: channel.type
        }));
    
    res.json(channels);
});

app.get('/api/guild/:guildId/roles', async (req, res) => {
    if (!req.isAuthenticated()) return res.status(401).json({ error: 'Non autorizzato' });
    
    const { guildId } = req.params;
    const guild = client.guilds.cache.get(guildId);
    
    if (!guild) {
        return res.status(404).json({ error: 'Server non trovato' });
    }
    
    const roles = guild.roles.cache
        .filter(role => !role.managed && role.name !== '@everyone')
        .map(role => ({
            id: role.id,
            name: role.name,
            color: role.hexColor
        }));
    
    res.json(roles);
});

app.post('/api/moderators', async (req, res) => {
    if (!req.isAuthenticated()) return res.status(401).json({ error: 'Non autorizzato' });
    
    const { guildId, userId } = req.body;
    
    try {
        await Guild.findOneAndUpdate(
            { guildId },
            { 
                $push: { 
                    moderators: {
                        userId,
                        permissions: {
                            manageBans: false,
                            manageKicks: false,
                            manageRoles: false,
                            manageChannels: false,
                            manageMessages: false,
                            viewLogs: true,
                            manageSettings: false
                        }
                    }
                }
            },
            { upsert: true }
        );
        res.json({ success: true });
    } catch (error) {
        res.status(500).json({ error: 'Errore del server' });
    }
});

app.delete('/api/moderators', async (req, res) => {
    if (!req.isAuthenticated()) return res.status(401).json({ error: 'Non autorizzato' });
    
    const { guildId, userId } = req.body;
    
    try {
        await Guild.findOneAndUpdate(
            { guildId },
            { $pull: { moderators: { userId } } }
        );
        res.json({ success: true });
    } catch (error) {
        res.status(500).json({ error: 'Errore del server' });
    }
});

app.post('/api/settings', async (req, res) => {
    if (!req.isAuthenticated()) return res.status(401).json({ error: 'Non autorizzato' });
    
    const { guildId, setting, enabled } = req.body;
    
    try {
        await Guild.findOneAndUpdate(
            { guildId },
            { [`settings.${setting}`]: enabled },
            { upsert: true }
        );
        res.json({ success: true });
    } catch (error) {
        res.status(500).json({ error: 'Errore del server' });
    }
});

app.post('/api/log-channels', async (req, res) => {
    if (!req.isAuthenticated()) return res.status(401).json({ error: 'Non autorizzato' });
    
    const { guildId, logChannels } = req.body;
    
    try {
        await Guild.findOneAndUpdate(
            { guildId },
            { logChannels },
            { upsert: true }
        );
        res.json({ success: true });
    } catch (error) {
        res.status(500).json({ error: 'Errore del server' });
    }
});

app.post('/api/verification', async (req, res) => {
    if (!req.isAuthenticated()) return res.status(401).json({ error: 'Non autorizzato' });
    
    const { guildId, verification } = req.body;
    
    try {
        await Guild.findOneAndUpdate(
            { guildId },
            { verification },
            { upsert: true }
        );
        res.json({ success: true });
    } catch (error) {
        res.status(500).json({ error: 'Errore del server' });
    }
});

app.post('/api/send-verification-message', async (req, res) => {
    if (!req.isAuthenticated()) return res.status(401).json({ error: 'Non autorizzato' });

    const { guildId } = req.body;

    try {
        const guildData = await Guild.findOne({ guildId });
        if (!guildData) {
            return res.status(404).json({ error: 'Dati della gilda non trovati.' });
        }

        const guild = client.guilds.cache.get(guildId);
        if (!guild) {
            return res.status(404).json({ error: 'Bot non presente in questa gilda.' });
        }

        const verifyChannel = guild.channels.cache.get(guildData.verification.channelId);
        if (!verifyChannel) {
            return res.status(400).json({ error: 'Canale di verifica non configurato o non trovato.' });
        }

        if (!verifyChannel.permissionsFor(guild.members.me).has([PermissionsBitField.Flags.SendMessages, PermissionsBitField.Flags.EmbedLinks])) {
            return res.status(403).json({ error: 'Bot non ha permessi per inviare messaggi nel canale di verifica.' });
        }

        const embed = new EmbedBuilder()
            .setTitle('🔒 Verifica Richiesta')
            .setDescription(guildData.verification.message)
            .setColor(guildData.verification.embedColor)
            .setThumbnail('https://media.discordapp.net/attachments/1417150708704084122/1417567764331233401/azzurro-e-bianco.png')
            .setFooter({ text: 'Sefion Security - Clicca il pulsante sotto per verificarti', iconURL: guild.iconURL() });

        let components = [];
        let captchaAttachment = null;

        if (guildData.verification.captchaEnabled) {
            const captcha = await generateCaptcha();
            captchaAttachment = new AttachmentBuilder(captcha.buffer, { name: 'captcha.png' });
            
            embed.setImage('attachment://captcha.png');
            embed.addFields({ name: '🔤 Codice Captcha', value: 'Inserisci il codice mostrato nell\'immagine cliccando il pulsante', inline: false });
            
            const button = new ButtonBuilder()
                .setCustomId(`verify_captcha_${captcha.text}`)
                .setLabel('🔓 Inserisci Codice')
                .setStyle(ButtonStyle.Primary);
            
            components = [new ActionRowBuilder().addComponents(button)];
        } else {
            const button = new ButtonBuilder()
                .setCustomId(`verify_normal`)
                .setLabel('✅ Verificati')
                .setStyle(ButtonStyle.Success);
            
            components = [new ActionRowBuilder().addComponents(button)];
        }

        let sentMessage;
        if (guildData.verification.verificationMessageId) {
            try {
                const oldMessage = await verifyChannel.messages.fetch(guildData.verification.verificationMessageId);
                await oldMessage.delete();
            } catch (deleteError) {
                console.warn(`Impossibile cancellare il vecchio messaggio di verifica: ${deleteError.message}`);
            }
        }

        const messageOptions = {
            embeds: [embed],
            components: components
        };
        if (captchaAttachment) {
            messageOptions.files = [captchaAttachment];
        }

        sentMessage = await verifyChannel.send(messageOptions);
        
        guildData.verification.verificationMessageId = sentMessage.id;
        await guildData.save();

        res.json({ success: true, messageId: sentMessage.id });

    } catch (error) {
        console.error('Errore invio messaggio verifica:', error);
        res.status(500).json({ error: 'Errore durante l\'invio del messaggio di verifica.', details: error.message });
    }
});

app.get('/api/guild/:guildId', async (req, res) => {
    if (!req.isAuthenticated()) return res.status(401).json({ error: 'Non autorizzato' });
    
    const { guildId } = req.params;
    
    try {
        let guildData = await Guild.findOne({ guildId });
        if (!guildData) {
            guildData = await new Guild({
                guildId,
                ownerId: req.user.id 
            }).save();
        }
        
        res.json(guildData);
    } catch (error) {
        console.error('Errore caricamento gilda:', error);
        res.status(500).json({ error: 'Errore del server' });
    }
});

app.get('/logout', (req, res) => {
    req.logout((err) => {
        if (err) return next(err);
        res.redirect('/');
    });
});

client.login(process.env.DISCORD_BOT_TOKEN);

process.on('unhandledRejection', (reason, promise) => {
    console.error('❌ Unhandled Rejection at:', promise, 'reason:', reason);
});

process.on('uncaughtException', (error) => {
    console.error('❌ Uncaught Exception:', error);
});

app.listen(3000, () => {
    console.log('🚀 Sefion Security Bot Dashboard avviata su http://localhost:3000');
    console.log('🛡️ Bot di sicurezza in avvio...');
    console.log('📊 Dashboard web disponibile');
    console.log('🔧 Ricorda di configurare le variabili d\'ambiente');
    console.log('© 2025 Sefion Security - Tutti i diritti riservati');
});


