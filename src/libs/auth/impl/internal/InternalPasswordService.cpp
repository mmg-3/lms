/*
 * Copyright (C) 2019 Emeric Poupon
 *
 * This file is part of LMS.
 *
 * LMS is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * LMS is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with LMS.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "InternalPasswordService.hpp"

#include <Wt/WRandom.h>

#include "auth/Types.hpp"
#include "database/Session.hpp"
#include "database/User.hpp"
#include "utils/Exception.hpp"
#include "utils/Logger.hpp"

namespace Auth
{
	InternalPasswordService::InternalPasswordService(std::size_t maxThrottlerEntries)
		: PasswordServiceBase {maxThrottlerEntries}
	{
		_validator.setMinimumLength(Wt::Auth::PasswordStrengthType::OneCharClass, 4);
		_validator.setMinimumLength(Wt::Auth::PasswordStrengthType::TwoCharClass, 4);
		_validator.setMinimumLength(Wt::Auth::PasswordStrengthType::PassPhrase, 4);
		_validator.setMinimumLength(Wt::Auth::PasswordStrengthType::ThreeCharClass, 4);
		_validator.setMinimumLength(Wt::Auth::PasswordStrengthType::FourCharClass, 4);
		_validator.setMinimumPassPhraseWords(1);
		_validator.setMinimumMatchLength(3);
	}

	bool
	InternalPasswordService::checkUserPassword(Database::Session& session,
			std::string_view loginName,
			std::string_view password)
	{
		Database::User::PasswordHash passwordHash;
		{
			auto transaction {session.createSharedTransaction()};

			const Database::User::pointer user {Database::User::getByLoginName(session, loginName)};
			if (!user)
			{
				// hash random stuff here to waste some time
				_hashFunc.verify(Wt::WRandom::generateId(8), Wt::WRandom::generateId(8), Wt::WRandom::generateId(8));
				return false;
			}

			// Don't allow users being created
			passwordHash = user->getPasswordHash();
			if (passwordHash.salt.empty() || passwordHash.hash.empty())
			{
				// hash random stuff here to waste some time
				_hashFunc.verify(Wt::WRandom::generateId(8), Wt::WRandom::generateId(8), Wt::WRandom::generateId(8));
				return false;
			}
		}

		{
			LMS_LOG(AUTH, DEBUG) << "Checking internal password for user '" << loginName << "'";
			return _hashFunc.verify(std::string {password}, std::string {passwordHash.salt}, std::string {passwordHash.hash});
		}
	}

	bool
	InternalPasswordService::canSetPasswords() const
	{
		return true;
	}

	bool
	InternalPasswordService::isPasswordSecureEnough(std::string_view loginName, std::string_view password) const
	{
		return _validator.evaluateStrength(std::string {password}, std::string {loginName}, "").isValid();
	}

	void
	InternalPasswordService::setPassword(Database::User::pointer user, std::string_view newPassword)
	{
		if (!isPasswordSecureEnough(user->getLoginName(), newPassword))
			throw PasswordTooWeakException {};

		user.modify()->setPasswordHash(hashPassword(newPassword));
		user.modify()->clearAuthTokens();
	}

	Database::User::PasswordHash
	InternalPasswordService::hashPassword(std::string_view password) const
	{
		const std::string salt {Wt::WRandom::generateId(32)};

		return {salt, _hashFunc.compute(std::string {password}, salt)};
	}

} // namespace Auth

