import * as orm from "typeorm";
import Account from "./Account";
import Person from "../../cre-db-shared/models/Person";

@orm.SingleEntityChild()
export default class LocalAuthPerson extends Person {
    @orm.OneToOne(t => Account, a => a.person, { nullable: true })
    public account?: Account;
}
