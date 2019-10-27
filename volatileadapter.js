// "Volatile" storage adapter

const LRU = require("lru-cache");
const MAX_TTL = 1000 * 300; // Everything should last at most 5min
const store = new LRU({});

// Privates
function grantName(id){
    // Same as memory-adapter
    return "grant:" + id;
}
function uidName(id){
    // Same as memory-adapter
    return "sessionUid:" + id;
}
function usercodeName(code){
    // Same as memory-adapter
    return "userCode:" + code;
}

function limitTTL(ttl){
    return Math.min(ttl, MAX_TTL);
}

function store_set(key, obj, expire_sec){
    //console.log("set", key, obj);
    store.set(key, obj, limitTTL(expire_sec * 1000));
}

function store_get(key){
    const obj = store.get(key);
    //console.log("get", key, obj);
    return obj;
}

// Class VolatileAdapter
class VolatileAdapter {
    // 
    key(id){
        // Same as memory-adapter
        return this.model + id;
    }

    // Public APIs
    constructor(obj){
        // Same as memory-adapter
        this.model = obj;
    }

    async upsert(id, payload, expiresIn){
        const key = this.key(id);
        if(this.model === "Session"){
            store_set(uidName(payload.uid), id, expiresIn);
        }

        const { grantId, userCode } = payload;
        
        if(grantId){
            const keyname = grantName(grantId);
            const grant = store.get(keyname);
            if(! grant){
                store.set(keyname, [key]);
            }else{
                grant.push(key);
            }
        }

        if(userCode){
            store_set(usercodeName(userCode), id, expiresIn);
        }

        store_set(key, payload, expiresIn);
    }

    async find(id){
        return store_get(this.key(id));
    }

    async findByUserCode(code){
        const id = store_get(usercodeName(code));
        return this.find(id);
    }

    async findByUid(code){
        const id = store_get(uidName(code));
        return this.find(id);
    }

    async consume(id){
        let obj = await this.find(id);
        obj.consumed = true;
    }

    async destroy(id){
        store.del(this.key(id));
    }

    async revokeByGrantId(grantId){
        const keyname = grantName(grantId);
        const grant = store_get(keyname);

        if(grant){
            grant.forEach(e => store.del(e));
            store.del(keyname);
        }
    }
}

module.exports = VolatileAdapter;
