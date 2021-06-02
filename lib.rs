#![cfg_attr(not(feature = "std"), no_std)]

use ink_lang as ink;

// const DEFAULT_ENDOWMENT: Balance = 1_000_000;
// const DEFAULT_GAS_LIMIT: Balance = 1_000_000;

#[ink::contract]
mod myns {
    use ink_env::{self, hash::Blake2x256};
    use ink_prelude::format;
    use ink_prelude::string::String;
    use ink_prelude::vec::Vec;
    use ink_storage::collections::HashMap as StorageHashMap;
    use scale::Encode;

    /// Defines the storage of your contract.
    /// Add new fields to the below struct in order
    /// to add new static storage fields to your contract.
    #[ink(storage)]
    #[derive(Default)]
    pub struct Myns {
        /// Stores a name with it's owner
        registry: StorageHashMap<Hash, (AccountId, BlockNumber, u32)>,
        commit_name: StorageHashMap<Hash, Hash>,
        commit: StorageHashMap<Hash, BlockNumber>,
    }

    /// Emitted whenever a new name is being registered.
    #[ink(event)]
    pub struct Register {
        #[ink(topic)]
        name: Hash,
        #[ink(topic)]
        from: AccountId,
    }

    /// Emitted whenever a new name is being registered.
    #[ink(event)]
    pub struct Unregister {
        #[ink(topic)]
        name: Hash,
    }

    impl Myns {
        /// Constructors can delegate to other constructors.
        #[ink(constructor)]
        pub fn new() -> Self {
            Default::default()
        }

        /// Simply returns the current Hash value of our `name`.
        #[ink(message)]
        pub fn get_hash_name(&self, name: String) -> Hash {
            Hash::from(self.env().hash_bytes::<Blake2x256>(name.as_bytes()))
        }

        #[ink(message)]
        pub fn rent_price(&self, name: String, duration: u32) -> Balance {
            let rp = name.as_bytes().len() as u32 * duration * 1_000;
            ink_env::debug_println(
                format!("rent_price {} for {} is {}", name, duration, rp).as_str(),
            );
            Balance::from(rp)
        }

        #[ink(message)]
        pub fn valid(&self, name: String) -> bool {
            let l = name.as_bytes().len();
            ink_env::debug_println(format!("name size {} is {}", name, l).as_str());
            l <= 32
        }

        #[ink(message)]
        pub fn available(&self, name: String) -> bool {
            if self.valid(name.clone()) {
                let h = self.get_hash_name(name);
                if let Some((_, ref b, ref d)) = self.registry.get(&h) {
                    let t = self.env().block_number() - *b;
                    ink_env::debug_println(format!("available: {} == {}", t, *d).as_str());
                    *d <= t
                } else {
                    true
                }
            } else {
                false
            }
        }

        #[ink(message, selector = "0x1EECBEEF")]
        pub fn make_commitment(&self, name: String, owner: AccountId, secret: u32) -> Hash {
            let mut out = [0; 32];
            let mut pimage: Vec<u8> = Vec::new();
            pimage.extend_from_slice(name.as_bytes());
            let enc_owner = owner.encode();
            pimage.extend_from_slice(&enc_owner[..]);
            pimage.extend_from_slice(&secret.to_be_bytes());
            ink_env::debug_println(format!("preimage: {:?}", pimage).as_str());
            ink_env::hash_bytes::<Blake2x256>(&pimage, &mut out);
            ink_env::debug_println(format!("commitment: {:?}", out).as_str());
            Hash::from(out)
        }

        pub fn not_expired(&self, hash_name: Hash) -> Option<(&AccountId, &BlockNumber, &u32)> {
            if let Some((ref a, ref b, ref d)) = self.registry.get(&hash_name) {
                let t = self.env().block_number() - *b;
                ink_env::debug_println(format!("not_expired: {} == {}", t, *d).as_str());
                if t <= *d {
                    Some((a, b, d))
                } else {
                    None
                }
            } else {
                None
            }
        }

        pub fn expired(&self, hash_name: Hash) -> Option<(&AccountId, &BlockNumber, &u32)> {
            if let Some((ref a, ref b, ref d)) = self.registry.get(&hash_name) {
                let t = self.env().block_number() - *b;
                ink_env::debug_println(format!("expired: {} == {}", t, *d).as_str());
                if t > *d {
                    Some((a, b, d))
                } else {
                    None
                }
            } else {
                None
            }
        }

        fn not_expired_commit(&self, b: &BlockNumber) -> bool {
            let t = self.env().block_number() - *b;
            ink_env::debug_println(format!("not_expired_commit: {}", t).as_str());
            t <= 100
        }

        fn commit_check(&self, commitment: &Hash) {
            if let Some(ref b) = self.commit.get(commitment) {
                let valid = self.not_expired_commit(b);
                ink_env::debug_println(format!("commit still valid: {}", valid).as_str());
                assert!(valid, "commit still valid");
            }
            if let Some(name_hash) = self.commit_name.get(commitment) {
                let not_expired = self.not_expired(*name_hash).is_some();
                ink_env::debug_println(format!("name avaliable: {}", not_expired).as_str());
                assert!(not_expired, "name not avaliable");
            }
        }

        fn commit_register(&self, commitment: &Hash) {
            if let Some(ref b) = self.commit.get(commitment) {
                let not_expired_commit = self.not_expired_commit(b);
                ink_env::debug_println(
                    format!("commit not expired: {}", not_expired_commit).as_str(),
                );
                assert!(not_expired_commit, "commit expired");
            } else {
                ink_env::debug_println("no commit");
                panic!("no commit")
            }
        }

        #[ink(message, payable, selector = "0xDEADBEEF")]
        pub fn commit(&mut self, commitment: Hash) {
            let msg =
                ink_prelude::format!("received payment: {}", self.env().transferred_balance());
            ink_env::debug_println(&msg);
            assert!(
                self.env().transferred_balance() >= 10,
                "mininum payment is ten"
            );
            self.commit_check(&commitment);
            self.commit.insert(commitment, self.env().block_number());
            ink_env::debug_println("commited");
        }

        fn unlock_balance(&mut self, name_hash: Hash) {
            if let Some((ref a, _b, _d)) = self.registry.get(&name_hash) {
                match self.env().transfer(*a, 10) {
                    Err(ink_env::Error::BelowSubsistenceThreshold) => {
                        panic!(
                            "requested transfer would have brought contract\
                            below subsistence threshold!"
                        )
                    }
                    Err(_) => panic!("transfer failed!"),
                    Ok(_) => {}
                }
            }
            let _ = self.registry.take(&name_hash);
            let mut cn_values = self.commit_name.iter();
            let entry = cn_values.next();
            let mut nh = Hash::default();
            while entry.is_some() {
                if let Some(ref inner) = entry {
                    if *inner.1 == name_hash {
                        nh = *inner.0;
                        break;
                    }
                }
            }
            if nh != Hash::default() {
                let _ = self.commit_name.take(&nh);
            }
        }

        #[ink(message, payable, selector = "0xCAFEBABE")]
        pub fn register(&mut self, name: String, from: AccountId, duration: u32, secret: u32) {
            let msg =
                ink_prelude::format!("register payment: {}", self.env().transferred_balance());
            ink_env::debug_println(&msg);
            let r = self.rent_price(name.clone(), duration);
            assert!(
                self.env().transferred_balance() >= r + 10,
                "payment was not enough for rent plus 10 (locked balance)"
            );
            let commitment = self.make_commitment(name.clone(), from, secret);
            ink_env::debug_println(format!("commitment: {:?}", commitment).as_str());
            self.commit_register(&commitment);
            ink_env::debug_println(format!("name: {:?}", name).as_str());
            let available = self.available(name.clone());
            ink_env::debug_println(format!("avaliable: {:?}", available).as_str());
            assert!(available, "not available");
            let name_hash = self.get_hash_name(name);
            ink_env::debug_println(format!("name_hash: {:?}", name_hash).as_str());
            if let Some((_a, _b, _d)) = self.expired(name_hash) {
                self.unregister_unchecked(name_hash);
            }
            self.registry
                .insert(name_hash, (from, self.env().block_number(), duration));
            self.commit_name.insert(commitment, name_hash);
            self.commit.take(&commitment);
            self.env().emit_event(Register {
                name: name_hash,
                from,
            });
        }

        pub fn unregister_unchecked(&mut self, name: Hash) {
            let msg =
                ink_prelude::format!("unregister payment: {}", self.env().transferred_balance());
            ink_env::debug_println(&msg);
            self.unlock_balance(name);
            self.env().emit_event(Unregister { name });
        }

        pub fn is_owner(&self, name: Hash) -> bool {
            if let Some((ref o, _b, _d)) = self.registry.get(&name) {
                self.env().caller() == *o
            } else {
                false
            }
        }

        #[ink(message, selector = "0xDEADBABE")]
        pub fn unregister(&mut self, name: Hash) {
            if self.is_owner(name) {
                self.unregister_unchecked(name);
            } else {
                ink_env::debug_println("not the owner");
                panic!("not the owner");
            }
        }

        // #[ink(message, payable, selector = "0xCAFEBEEF")]
        // pub fn renew(&mut self, name: String, duration: u32) {
        //     let hash_name = self.get_hash_name(name);
        //     if let Some((ref o, ref b, ref d)) = self.registry.get(&hash_name) {
        //         let t = self.env().block_number() - *b;
        //         ink_env::debug_println(format!("elapsed: {} == {}", t, *d).as_str());

        //     } else {
        //         ink_env::debug_println("not registered");
        //         panic!("not registered");
        //     }
        // }
    }

    /// Unit tests in Rust are normally defined within such a `#[cfg(test)]`
    /// module and test functions are marked with a `#[test]` attribute.
    /// The below code is technically just normal Rust code.
    #[cfg(not(feature = "ink-experimental-engine"))]
    #[cfg(test)]
    mod tests {
        /// Imports all the definitions from the outer scope so we can use them here.
        use super::*;
        use ink_env::{call, test};
        /// Imports `ink_lang` so we can use `#[ink::test]`.
        use ink_lang as ink;

        /// We test if the default constructor does its job.
        #[ink::test]
        fn default_works() {
            let myns = Myns::default();
            assert!(true);
        }

        /// We test a simple use case of our contract.
        #[ink::test]
        fn register_works() {
            // given
            let contract_balance = 100;
            let accounts = default_accounts();
            set_sender(accounts.alice);
            set_balance(contract_id(), contract_balance);
            let mut myns = Myns::default();

            // when
            set_sender(accounts.eve);
            set_balance(accounts.eve, 100);

            assert!(myns.available("myname".to_owned()));
            let commitment = myns.make_commitment("myname".to_owned(), accounts.eve, 1);
            commit(&accounts.eve, &commitment);
            myns.commit(commitment);
            assert!(myns.available("myname".to_owned()));
            register("myname".to_owned(), &accounts.eve, 100, 1);
            myns.register("myname".to_owned(), accounts.eve, 100, 1);
            assert!(!myns.available("myname".to_owned()));
        }

        fn contract_id() -> AccountId {
            ink_env::test::get_current_contract_account_id::<ink_env::DefaultEnvironment>()
                .expect("Cannot get contract id")
        }

        fn set_sender(sender: AccountId) {
            let callee =
                ink_env::account_id::<ink_env::DefaultEnvironment>().unwrap_or([0x0; 32].into());
            test::push_execution_context::<Environment>(
                sender,
                callee,
                1000000,
                1000000,
                test::CallData::new(call::Selector::new([0x00; 4])), // dummy
            );
        }

        fn default_accounts() -> ink_env::test::DefaultAccounts<ink_env::DefaultEnvironment> {
            ink_env::test::default_accounts::<ink_env::DefaultEnvironment>()
                .expect("Off-chain environment should have been initialized already")
        }

        fn set_balance(account_id: AccountId, balance: Balance) {
            ink_env::test::set_account_balance::<ink_env::DefaultEnvironment>(account_id, balance)
                .expect("Cannot set account balance");
        }

        fn commit(account: &AccountId, commitment: &Hash) {
            // 0xDEADBEEF
            let mut data = ink_env::test::CallData::new(ink_env::call::Selector::new([
                0xDE, 0xAD, 0xBE, 0xEF,
            ]));
            data.push_arg(commitment);
            let mock_transferred_balance = 100;

            // Push the new execution context which sets Eve as caller and
            // the `mock_transferred_balance` as the value which the contract
            // will see as transferred to it.
            ink_env::test::push_execution_context::<ink_env::DefaultEnvironment>(
                *account,
                contract_id(),
                1000000,
                mock_transferred_balance,
                data,
            );
        }

        fn register(name: String, from: &AccountId, duration: u32, secret: u32) {
            // 0xCAFEBABE
            let mut data = ink_env::test::CallData::new(ink_env::call::Selector::new([
                0xCA, 0xFE, 0xBA, 0xBE,
            ]));
            data.push_arg(&name);
            data.push_arg(from);
            data.push_arg(&duration);
            data.push_arg(&secret);
            let mock_transferred_balance = 600010;

            // Push the new execution context which sets 'from' as caller and
            // the `mock_transferred_balance` as the value which the contract
            // will see as transferred to it.
            ink_env::test::push_execution_context::<ink_env::DefaultEnvironment>(
                *from,
                contract_id(),
                1000000,
                mock_transferred_balance,
                data,
            );
        }
    }
}
