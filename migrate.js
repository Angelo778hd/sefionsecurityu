require('dotenv').config();
const mongoose = require('mongoose');

// Usa il tuo schema esistente
const guildSchema = new mongoose.Schema({
    guildId: { type: String, required: true, unique: true },
    settings: {
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
    }
}, { strict: false }); // strict: false permette di leggere campi non validi

const Guild = mongoose.model('Guild', guildSchema);

async function migrate() {
    try {
        await mongoose.connect(process.env.MONGODB_URI);
        console.log('Connesso al database');
        
        // Trova tutti i documenti con punishmentType non validi
        const guilds = await Guild.find({}).lean();
        
        for (const guild of guilds) {
            const updates = {};
            let needsUpdate = false;
            
            const settingsToCheck = [
                'antiEmojiCreate', 'antiEmojiRename', 'antiEmojiDelete',
                'antiGhostPing', 'antiSpam', 'antiRaid'
            ];
            
            settingsToCheck.forEach(setting => {
                if (guild.settings && guild.settings[setting] && 
                    typeof guild.settings[setting].punishmentType !== 'string') {
                    
                    updates[`settings.${setting}.punishmentType`] = 'timeout';
                    needsUpdate = true;
                    console.log(`Correzione ${setting} per gilda ${guild.guildId}`);
                }
            });
            
            if (needsUpdate) {
                await Guild.updateOne({ _id: guild._id }, { $set: updates });
                console.log(`✅ Gilda ${guild.guildId} corretta`);
            }
        }
        
        console.log('🎉 Migrazione completata!');
        process.exit(0);
        
    } catch (error) {
        console.error('Errore migrazione:', error);
        process.exit(1);
    }
}

migrate();
