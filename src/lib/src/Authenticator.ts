import { runQuery } from "@sveltekit-board/db";
import { createHmac } from "crypto";

export default class Authenticator {
    static saltGeneratingFunction: (password: string) => string = (p) => p;

    /**
     * auth 테이블이 있는지, 테이블의 컬럼의 타입은 맞는지 체크합니다. 단, AUTO_INCREMENT 등의 **추가적인** 내용은 체크하지 않습니다.
     * @returns 
     */
    static async checkTable() {
        return await runQuery(async (run) => {
            const tables: string[] = (await run("SHOW TABLES")).map((e: any) => Object.values(e)[0])

            if (!tables.includes('auth')) return false;

            const columns: any[] = Object.values(await run("SHOW COLUMNS FROM `auth`"));

            if (authSchema.length > columns.length) return false;

            return authSchema.every(u => {
                const column = columns.find(c => c.Field === u.Field);
                if(!column) return false;
                return Object.keys(u).every(key => {
                    return u[key as keyof typeof u] === column[key];
                })
            })
        })
    }

    /**
     * auth 테이블을 생성합니다.
     */
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

    /**
     * auth 테이블을 검사하여 잘못된 부분을 고칩니다. 에러가 발생할 시 수동으로 테이블을 수정하여야합니다.
     * @returns 
     */
    static async fixTable(){
        return await runQuery(async(run) => {
            const result = await run("SHOW TABLES");
            const tables = result.map((e: any) => Object.values(e)[0]);
            if (!tables.includes('auth')){
                return await this.createTable();
            }

            const columns: any[] = Object.values(await run("SHOW COLUMNS from `auth`"));
            for(const u of authSchema){
                const column = columns.find(column => column.Field === u.Field);
                if(u.Extra === "auto_increment" && column && u.Extra !== column.Extra){
                    await run(`ALTER TABLE \`auth\` DROP \`${u.Field}\``);
                    await run(`ALTER TABLE \`auth\` ADD \`${u.Field}\` ${u.Type}${u.Default? ` DEFAULT '${u.Default}'`:''}${u.Null === "NO"? ' NOT NULL' : ''}${u.Extra === "auto_increment"? ` AUTO_INCREMENT FIRST, ADD PRIMARY KEY (\`${u.Field}\`)` : ''};`);
                    continue;
                }
                if(!column){
                    await run(`ALTER TABLE \`auth\` ADD \`${u.Field}\` ${u.Type}${u.Default? ` DEFAULT '${u.Default}'`:''}${u.Null === "NO"? ' NOT NULL' : ''}${u.Extra === "auto_increment"? ` AUTO_INCREMENT FIRST, ADD PRIMARY KEY (\`${u.Field}\`)` : ''};`);
                    continue;
                }
                if(column.Type !== u.Type || u.Default !== column.Default || u.Null !== column.Null){
                    await run(`ALTER TABLE \`auth\` CHANGE \`${u.Field}\` \`${u.Field}\` ${u.Type}${u.Default? ` DEFAULT '${u.Default}'`:''}${u.Null === "NO"? ' NOT NULL' : ''};`);
                }
            }
        })
    }

    /**
     * 비밀번호를 sha512 알고리즘으로 암호화합니다.
     * @param password 비밀번호
     * @returns 
     */
    static hash(password: string) {
        return createHmac('sha512', password + this.saltGeneratingFunction(password)).digest('hex')
    }

    /**
     * password를 받아 salt를 반환하는 함수를 설정합니다. 랜덤한 값이나 시간에 대한 값을 사용하면 회원 확인 시 오류가 생길 수 있습니다.
     * @param func password를 받아 salt를 반환하는 함수
     */
    static setSaltGeneratingFunction(func: (password: string) => string) {
        this.saltGeneratingFunction = func;
    }

    /**
     * 해당 id가 존재하는지 확인합니다.
     * @param id 
     * @returns 
     */
    static async existsId(id: string) {
        return await runQuery(async (run) => {
            return Boolean(Object.values((await run("SELECT EXISTS(SELECT * FROM `auth` WHERE `id` = ?);", [id]))[0])[0]);
        })
    }

    /**
     * 해당 id, password 쌍이 존재하는지 확인합니다.
     * @param id 
     * @param password 
     * @returns 
     */
    static async existsPair(id: string, password: string) {
        return await runQuery(async (run) => {
            return Boolean(Object.values((await run("SELECT EXISTS(SELECT * FROM `auth` WHERE `id` = ? AND `password` = ?);", [id, this.hash(password)]))[0])[0]);
        })
    }

    /**
     * 새로운 id, password 쌍을 생성합니다. password는 암호화되어 db에 저장됩니다. 만약 쌍이 이미 존재하면 false를, 쌍을 새로 생성했다면 true를 반환합니다.
     * @param id 
     * @param password 
     * @returns 
     */
    static async createNewPair(id: string, password: string) {
        return await runQuery(async (run) => {
            const existsId = Boolean(Object.values((await run("SELECT EXISTS(SELECT * FROM `auth` WHERE `id` = ?);", [id]))[0])[0]);

            if (existsId) return false;

            await run("INSERT INTO `auth` (`id`, `password`) VALUES (?, ?)", [id, this.hash(password)]);

            return true;
        })
    }
}

const authSchema = [
    {
        "Field": "order",
        "Type": "int(11)",
        "Null": "NO",
        "Key": "PRI",
        "Default": null,
        "Extra": "auto_increment"
    },
    {
        "Field": "id",
        "Type": "text",
        "Null": "NO",
        "Key": "",
        "Default": null,
        "Extra": ""
    },
    {
        "Field": "password",
        "Type": "mediumtext",
        "Null": "NO",
        "Key": "",
        "Default": null,
        "Extra": ""
    }
]