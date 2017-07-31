import * as orm from "typeorm";
import LocalAuthPerson from "./LocalAuthPerson";

@orm.Index(["person"], { unique: true })
@orm.Entity()
export default class Account {
    public constructor(init: Partial<Account>) {
        Object.assign(this, init);
    }

    @orm.PrimaryGeneratedColumn()
    public id: number;

    @orm.JoinColumn()
    @orm.OneToOne(t => LocalAuthPerson, p => p.account, { nullable: false })
    public person: LocalAuthPerson;

    @orm.Column({ type: "varchar", nullable: false })
    public password: string;

    @orm.Column({ type: "varchar", nullable: false })
    public salt: string;
}
