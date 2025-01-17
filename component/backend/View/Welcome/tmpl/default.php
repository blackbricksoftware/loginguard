<?php
/**
 * @package   AkeebaLoginGuard
 * @copyright Copyright (c)2016-2019 Nicholas K. Dionysopoulos / Akeeba Ltd
 * @license   GNU General Public License version 3, or later
 */

use Joomla\CMS\Factory;
use Joomla\CMS\Router\Route;

// Prevent direct access
defined('_JEXEC') or die;

/** @var \Akeeba\LoginGuard\Admin\View\Welcome\Html $this */

?>

<?php if ($this->noMethods || $this->notInstalled || $this->noSystemPlugin): ?>
<div class="akeeba-block--failure">
	<span class="akeeba-label--failure"><?php echo JText::_('COM_LOGINGUARD_STATUS_NOTREADY'); ?></span>
	<?php echo JText::_('COM_LOGINGUARD_STATUS_NOTREADY_INFO'); ?>
</div>
<?php elseif ($this->noGeoIP || $this->noUserPlugin): ?>
<div class="akeeba-block--warning">
	<span class="akeeba-label--warning"><?php echo JText::_('COM_LOGINGUARD_STATUS_ALMOSTREADY'); ?></span>
	<?php echo JText::_('COM_LOGINGUARD_STATUS_ALMOSTREADY_INFO'); ?>
</div>
<?php else: ?>
<div class="akeeba-block--success">
	<span class="akeeba-label--success"><?php echo JText::_('COM_LOGINGUARD_STATUS_READY'); ?></span>
	<?php echo JText::_('COM_LOGINGUARD_STATUS_READY_INFO'); ?>
</div>
<?php endif; ?>

<?php if ($this->notInstalled): ?>
<div class="akeeba-panel--danger">
    <header class="akeeba-block-header">
        <h3>
            <span class="akion-power"></span>
            <span>
                <?php echo JText::_('COM_LOGINGUARD_ERR_NOPLUGINS_HEAD'); ?>
            </span>
        </h3>
    </header>
    <p>
        <?php echo JText::_('COM_LOGINGUARD_ERR_PLUGINS_INFO_COMMON'); ?>
        <?php echo JText::_('COM_LOGINGUARD_ERR_NOPLUGINS_INFO'); ?>
    </p>
</div>
<?php elseif ($this->noMethods): ?>
<div class="akeeba-panel--danger">
    <header class="akeeba-block-header">
        <h3>
            <span class="akion-android-warning"></span>
            <span>
                <?php echo JText::_('COM_LOGINGUARD_ERR_NOTINSTALLEDPLUGINS_HEAD'); ?>
            </span>
        </h3>
    </header>
    <p>
	    <?php echo JText::_('COM_LOGINGUARD_ERR_PLUGINS_INFO_COMMON'); ?>
	    <?php echo JText::_('COM_LOGINGUARD_ERR_NOTINSTALLEDPLUGINS_INFO'); ?>
    </p>
</div>
<?php endif; ?>
<?php if ($this->noSystemPlugin): ?>
<div class="akeeba-panel--warning">
    <header class="akeeba-block-header">
        <h3>
            <span class="akion-android-warning"></span>
            <span>
            <?php echo JText::_('COM_LOGINGUARD_ERR_NOSYSTEM_HEAD'); ?>
        </span>
        </h3>
    </header>
    <p>
        <?php echo JText::_('COM_LOGINGUARD_ERR_NOSYSTEM_INFO'); ?>
    </p>
</div>
<?php endif; ?>

<?php if ($this->noUserPlugin): ?>
<div class="akeeba-panel--warning">
    <header class="akeeba-block-header">
        <h3>
            <span class="akion-android-warning"></span>
            <span>
        <?php echo JText::_('COM_LOGINGUARD_ERR_NOUSER_HEAD'); ?>
    </span>
        </h3>
    </header>
    <p>
        <?php echo JText::_('COM_LOGINGUARD_ERR_NOUSER_INFO'); ?>
    </p>
</div>
<?php endif; ?>

<?php if ($this->needsMigration && !$this->notInstalled && !$this->noMethods && !$this->noSystemPlugin): ?>
<div class="akeeba-panel--info">
    <header class="akeeba-block-header">
        <h3>
            <span class="akion-android-lock"></span>
            <span>
                <?php echo JText::_('COM_LOGINGUARD_LBL_CONVERT_HEAD'); ?>
            </span>
        </h3>
    </header>
    <p>
		<?php echo JText::_('COM_LOGINGUARD_LBL_CONVERT_INFO'); ?>
    </p>
    <p>
        <a href="<?php echo Route::_('index.php?option=com_loginguard&task=convert.convert&' . $this->getContainer()->platform->getToken() . '=1')?>"
           class="akeeba-btn--success--large">
            <span class="akion-play"></span>
		    <?php echo JText::_('COM_LOGINGUARD_BTN_CONVERT'); ?>
        </a>
    </p>
</div>
<?php endif; ?>

<?php if ($this->noGeoIP): ?>
<div class="akeeba-panel--info">
    <header class="akeeba-block-header">
        <h3>
            <span class="akion-android-wifi"></span>
            <?php echo JText::_('COM_LOGINGUARD_ERR_GEOIP_NOTINSTALLED_HEAD'); ?>
        </h3>
    </header>
    <p>
        <?php echo JText::_('COM_LOGINGUARD_ERR_GEOIP_NOTINSTALLED_BODY'); ?>
    </p>
    <p>
        <a href="https://www.akeebabackup.com/download/akgeoip.html" target="_blank"
           class="akeeba-btn--primary">
            <span class="akion-ios-cloud-download"></span>
            <?php echo JText::_('COM_LOGINGUARD_ERR_GEOIP_NOTINSTALLED_BUTTON'); ?>
        </a>
    </p>
</div>
<?php elseif ($this->geoIPNeedsUpdate): ?>
<div class="akeeba-panel--info">
    <header class="akeeba-block-header">
        <h3>
            <span class="akion-refresh"></span>
            <?php echo JText::_('COM_LOGINGUARD_LBL_GEOIP_UPDATE_HEAD'); ?>
        </h3>
    </header>
    <p>
        <?php echo JText::_('COM_LOGINGUARD_LBL_GEOIP_UPDATE_BODY'); ?>
    </p>
    <p>
        <a href="<?php echo Route::_('index.php?option=com_loginguard&view=welcome&task=updategeoip&' . Factory::getSession()->getToken() . '=1') ?>"
           class="akeeba-btn--primary">
            <span class="akion-refresh"></span>
            <?php echo JText::_('COM_LOGINGUARD_LBL_GEOIP_UPDATE_BUTTON'); ?>
        </a>
    </p>
</div>
<?php elseif ($this->geoIPNeedsUpgrade): ?>
<div class="akeeba-panel--info">
    <header class="akeeba-block-header">
        <h3>
            <span class="akion-refresh"></span>
            <?php echo JText::_('COM_LOGINGUARD_LBL_GEOIP_UPGRADE_HEAD'); ?>
        </h3>
    </header>
	<p>
		<?php echo JText::_('COM_LOGINGUARD_LBL_GEOIP_UPGRADE_BODY'); ?>
	</p>
    <p>
        <a href="<?php echo Route::_('index.php?option=com_loginguard&view=welcome&task=upgradegeoip&' . Factory::getSession()->getToken() . '=1')?>"
           class="akeeba-btn--ghost">
            <span class="akion-refresh"></span>
		    <?php echo JText::_('COM_LOGINGUARD_LBL_GEOIP_UPGRADE_BUTTON'); ?>
        </a>
    </p>
</div>
<?php endif; ?>

<div class="akeeba-panel--primary">
    <header class="akeeba-block-header">
        <h2>
            <?php echo JText::_('COM_LOGINGUARD_LBL_MANAGE_HEAD'); ?>
        </h2>
    </header>
    <p>
        <?php echo JText::_('COM_LOGINGUARD_LBL_MANAGE_BODY'); ?>
    </p>
    <p>
        <a href="<?php echo Route::_('index.php?option=com_loginguard&task=methods.display') ?>" class="akeeba-btn--primary--large">
            <span class="akion-android-lock"></span>
            <?php echo JText::_('COM_LOGINGUARD_BTN_MANAGE_SELF'); ?>
        </a>
        <a href="<?php echo Route::_('index.php?option=com_users') ?>" class="akeeba-btn--ghost--small">
            <span class="akion-person-stalker"></span>
            <?php echo JText::_('COM_LOGINGUARD_BTN_MANAGE_OTHERS'); ?>
        </a>
    </p>
</div>
