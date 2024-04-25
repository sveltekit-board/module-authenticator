import { runQuery } from "@sveltekit-board/db";
import { createHmac } from "crypto";

export default class Authenticator {
    static saltGeneratingFunction: (password: string) => string = (p) => p;

    static async checkTable() {
        return await runQuery(async (run) => {
            const tables: string[] = (await run("SHOW TABLES")).map((e: any) => Object.values(e)[0])

            if (!tables.includes('auth')) return false;

            const columns: any[] = (await run("SHOW COLUMNS FROM `auth`"))
            const columnFields = {
                'order': 'int(11)',
                'id': 'text',
                'password': 'mediumtext'
            }

            let b = true;

            if (Object.keys(columnFields).length !== columns.length) b = false;;

            b = Object.keys(columnFields).every((key: any) => {
                return columns.find(column => column.Field === key)?.Type === columnFields[key as keyof typeof columnFields]
            })

            if (!b) {
                await runQuery(async (run) => {
                    await run("DROP TABLE `auth`");
                })
            }

            return b;
        })
    }

    static async createTable() {
        return await runQuery(async (run) => {
            await run(/*sql*/`
            CREATE TABLE \`auth\` (
                \`order\` int(11) NOT NULL,
                \`id\` text NOT NULL,
                \`password\` mediumtext NOT NULL
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
            `)

            await run(/*sql*/"ALTER TABLE `auth` ADD PRIMARY KEY (`order`);")

            await run(/*sql*/`ALTER TABLE \`auth\` MODIFY \`order\` int(11) NOT NULL AUTO_INCREMENT;`)
        })
    }

    static hash(password: string) {
        return createHmac('sha512', password + this.saltGeneratingFunction(password)).digest('hex')
    }

    static setSaltGeneratingFunction(func: (password: string) => string) {
        this.saltGeneratingFunction = func;
    }

    static async existsId(id: string) {
        return await runQuery(async (run) => {
            return Boolean(Object.values((await run("SELECT EXISTS(SELECT * FROM `auth` WHERE `id` = ?);", [id]))[0])[0]);
        })
    }

    static async createNewPair(id: string, password: string) {
        return await runQuery(async (run) => {
            const existsPair = Boolean(Object.values((await run("SELECT EXISTS(SELECT * FROM `auth` WHERE `id` = ?);", [id]))[0])[0]);

            if (existsPair) return false;

            await run("INSERT INTO `auth` (`id`, `password`) VALUES (?, ?)", [id, this.hash(password)]);

            return true;
        })
    }
}