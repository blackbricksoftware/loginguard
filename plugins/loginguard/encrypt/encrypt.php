<?php
/**
 * @package   AkeebaLoginGuard
 * @copyright Copyright (c)2016-2018 Nicholas K. Dionysopoulos / Akeeba Ltd
 * @license   GNU General Public License version 3, or later
 */

// Prevent direct access
use FOF30\Input\Input;

defined('_JEXEC') or die;

// Minimum PHP version check
if (!version_compare(PHP_VERSION, '5.4.0', '>='))
{
	return;
}

/**
 * Work around the very broken and completely defunct eAccelerator on PHP 5.4 (or, worse, later versions).
 */
if (function_exists('eaccelerator_info'))
{
	$isBrokenCachingEnabled = true;

	if (function_exists('ini_get') && !ini_get('eaccelerator.enable'))
	{
		$isBrokenCachingEnabled = false;
	}

	if ($isBrokenCachingEnabled)
	{
		/**
		 * I know that this define seems pointless since I am returning. This means that we are exiting the file and
		 * the plugin class isn't defined, so Joomla cannot possibly use it.
		 *
		 * Well, that is how PHP works. Unfortunately, eAccelerator has some "novel" ideas about how to go about it.
		 * For very broken values of "novel". What does it do? It ignores the return and parses the plugin class below.
		 *
		 * You read that right. It ignores ALL THE CODE between here and the class declaration and parses the
		 * class declaration. Therefore the only way to actually NOT load the  plugin when you are using it on a
		 * server where an irresponsible sysadmin has installed and enabled eAccelerator (IT'S END OF LIFE AND BROKEN
		 * PER ITS CREATORS FOR CRYING OUT LOUD) is to define a constant and use it to return from the constructor
		 * method, therefore forcing PHP to return null instead of an object. This prompts Joomla to not do anything
		 * with the plugin.
		 */
		if (!defined('AKEEBA_EACCELERATOR_IS_SO_BORKED_IT_DOES_NOT_EVEN_RETURN'))
		{
			define('AKEEBA_EACCELERATOR_IS_SO_BORKED_IT_DOES_NOT_EVEN_RETURN', 3245);
		}

		return;
	}
}

// Make sure Akeeba LoginGuard is installed
if (!file_exists(JPATH_ADMINISTRATOR . '/components/com_loginguard'))
{
	return;
}

// Load FOF
if (!defined('FOF30_INCLUDED') && !@include_once(JPATH_LIBRARIES . '/fof30/include.php'))
{
	return;
}

/**
 * Akeeba LoginGuard Plugin for encrypting the data at rest.
 *
 * This plugin intercepts the LoginGuard TFA records read and written to the database, applying cryptography to the
 * "options" property which stores the configuration information for the authentication method. The encryption key is
 * a randomly generated key, stored in the file secretkey.php inside the plugin's directory. If it cannot be created
 * automatically you need to create it yourself with the following contents:
 *
 * <?php defined('_JEXEC') or die();
 * define('AKEEBA_LOGINGUARD_ENCRYPT_KEY', 'YOUR_PASSWORD_HERE');
 *
 * where YOUR_PASSWORD_HERE is a long, random password. We recommend creating one with the random password generator at
 * https://www.random.org/passwords/?num=1&len=24&format=html&rnd=new
 *
 * WARNING! Encrypting your LoginGuard configuration DOES NOT offer the same kind of protection as "encrypting" the
 * login passwords. In fact, Joomla (and WordPress, Drupal, Magento etc) does not store passwords "encrypted", it stores
 * them _hashed_. Hashing is highly asymmetrical: deriving the hash from a password takes milliseconds whereas deriving
 * the password from a hash takes anywhere from hours to millions of years. Encryption is highly symmetrical: getting
 * the encrypted version of unencrypted information _and_ getting the unencrypted information from its encrypted version
 * takes milliseconds, in both cases. The use of reversible encryption in LoginGuard is stipulated by the kind of data
 * being stored: we need the raw, unencrypted data as a _seed_ to generate a temporary, single-use authentication code
 * be it a six digit time-based one time password or a cryptographic U2F signature. Passwords, on the other hand, are
 * entirely different. Passwords are immutable _and_ are provided in the plain ("unencrypted") when the user logs in.
 * This means that you can generate the hash of the password provided by the user in the login form, which takes mere
 * milliseconds, and compare it with the hash stored in the database without having to reverse the hash at any point
 * (which would take millions of years!). This is only possible because of the immutability of passwords. Long story
 * cut short, if an attacker gets hold of *BOTH* your site's database *AND* its files they can very easily decrypt the
 * LoginGuard information. This is a perfectly acceptable risk since LoginGuard is a second authentication step, meant
 * to protect the user against their password being stolen somewhere outside of your server. Second authentication steps
 * DO NOT protect against your server being already compromised. This largely makes the point of encrypting the
 * LoginGuard configuration information rather moot which is why this plugin is disabled by default. The benefits of
 * encrypting LoginGuard's configuration are confined to very limited use cases, e.g. the Joomla! login being used as
 * a single sign on (SSO) method for a valuable asset and the Joomla! site's database (but NOT its files) may be read by
 * untrusted agents. This is, of course, A MASSIVE OPERATIONAL SECURITY FAILURE. We DO NOT recommend using LoginGuard
 * options encryption as your last line of defense in this kind of situations. Basically, if you find yourself in a
 * situation where you _need_ to enable this plugin YOUR SITE HAS ALREADY BEEN "PWNED" (COMPROMISED) AND YOU ARE GOING
 * TO REGRET YOUR BAD DECISIONS. We accept NO RESPONSIBILITY WHATSOEVER per the license of the software. YOU HAVE BEEN
 * WARNED. Then why do we have this plugin? Bluntly put, because there are folks out there who don't understand
 * operational security and insist that having LoginGuard not encrypt its configuration is a "security risk" when, in
 * fact, the security risk comes from the reckless disregard of operational security managing the site. This plugin is,
 * therefore, little more than a placebo for these folks.
 */
class PlgLoginguardEncrypt extends JPlugin
{
	/**
	 * Caches the password used by this plugin to encrypt the LoginGuard information.
	 *
	 * @var  string
	 */
	private $password = '';

	public function __construct($subject, array $config = array())
	{
		parent::__construct($subject, $config);

		$this->password = $this->getSecretKey();
	}


	/**
	 * Encrypt the LoginGuard configuration before saving it to the database.
	 *
	 * @param   object $record The record being saved
	 *
	 * @return  void
	 *
	 * @throws  Exception
	 *
	 * @since   2.0.2
	 */
	public function onLoginGuardBeforeSaveRecord(&$record)
	{
		if (empty($this->password))
		{
			JFactory::getApplication()->enqueueMessage(JText::_('PLG_LOGINGUARD_ENCRYPT_ERR_CANTSAVEPASSWORD'), 'error');

			return;
		}

		// TODO Remove me
		return;

		$aes = new FOF30\Encrypt\Aes($this->password, 128, 'cbc');
		$record->options = '###AES128###' . $aes->encryptString($record->options);
	}

	/**
	 * Decrypt the LoginGuard configuration after reading it from the database.
	 *
	 * @param   JUser   $user    The user for which we are reading the LoginGuard record
	 * @param   object  $record  The LoginGuard record we read from the database
	 *
	 * @return  void
	 *
	 * @since   2.0.2
	 */
	public function onLoginGuardAfterReadRecord($user, &$record)
	{
		if (empty($this->password))
		{
			return;
		}

		// TODO Remove me
		return;

		if (substr($record->options, 0, 12) != '###AES128###')
		{
			// The settings are not encrypted yet. Flag them as in need to be saved again.
			$record->must_save = 1;

			return;
		}

		$aes = new FOF30\Encrypt\Aes($this->password, 128, 'cbc');
		$encrypted = substr($record->options, 12);
		$record->options = $aes->decryptString($encrypted);
	}

	/**
	 * Gets the secret key for settings encryption. If none exists yet, it will be generated for you.
	 *
	 * @return  string
	 *
	 * @return  void
	 *
	 * @since   2.0.2
	 */
	private function getSecretKey()
	{
		$keyFile = __DIR__ . '/secretkey.php';

		if (file_exists($keyFile))
		{
			include_once $keyFile;
		}

		if (!defined('AKEEBA_LOGINGUARD_ENCRYPT_KEY'))
		{
			$this->generateKey($keyFile);

			if (include_once($keyFile) === false)
			{
				return '';
			}
		}

		if (!defined('AKEEBA_LOGINGUARD_ENCRYPT_KEY'))
		{
			return '';
		}

		return AKEEBA_LOGINGUARD_ENCRYPT_KEY;
	}

	/**
	 * Generates a secret key file with a new, random key.
	 *
	 * @param   string  $keyFile  The path to the file where the key will be saved
	 *
	 * @return  void
	 *
	 * @since   2.0.2
	 */
	private function generateKey($keyFile)
	{
		$key = JUserHelper::genRandomPassword(32);

		$fileData = '<?' . "php\ndefined('_JEXEC') or die;\n\n";
		$fileData .= "define('AKEEBA_LOGINGUARD_ENCRYPT_KEY', '$key');\n";

		if (@file_put_contents($keyFile, $fileData) !== false)
		{
			return;
		}

		JFile::write($keyFile, $fileData);
	}
}
