import * as eta from "./eta";
import * as db from "./db";
import * as passport from "passport";
import { Strategy as LocalStrategy } from "passport-local";

export default class CasAuthProvider extends eta.IAuthProvider {
    public getPassportStrategy(): passport.Strategy {
        return new LocalStrategy((username: string, password: string, done: (err: Error, user?: db.Person | boolean) => void) => {
            this.onPassportVerify(username, password).then((person: db.Person) => {
                done(undefined, person === undefined ? false : person);
            }).catch(err => {
                done(err);
            });
        });
    }

    private async onPassportVerify(username: string, password: string): Promise<db.Person> {
        const account: db.Account = await db.account().createQueryBuilder("account")
            .leftJoinAndSelect("account.person", "person")
            .where(`"person"."username" = :username`, { username })
            .getOne();
        if (!account) return undefined;
        return account.verifyPassword(password) ? account.person : undefined;
    }

    public onPassportLogin(person: db.Person): Promise<void> {
        return Promise.resolve();
    }
}
