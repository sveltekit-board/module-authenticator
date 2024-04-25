import Authenticator from "$lib/src/Authenticator.js";

export async function load(){
    if(!await Authenticator.checkTable()){
        await Authenticator.createTable()
    }
    console.log(await Authenticator.createNewPair('adsd', 'asasddasd'))
}