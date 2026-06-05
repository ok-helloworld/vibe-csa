# PHP Tier 分类规则

## 文件扩展名

- `.php` — PHP 源文件

## Tier 分类

### T1（入口点，权重 1.0）

控制器、路由、处理器 —— 直接处理 HTTP 请求的类/函数。

**Laravel**:
- 文件路径包含 `app/Http/Controllers/`
- 继承 `Controller` 基类
- 方法上有路由指向（查 `routes/web.php`、`routes/api.php`）

**Symfony**:
- 包含 `@Route` 注解的 Controller 方法
- 文件路径包含 `src/Controller/`
- 继承 `AbstractController`

**ThinkPHP**:
- 文件路径包含 `app/controller/` 或 `application/controller/`
- 继承 `Controller` 基类

**WordPress**:
- 包含 `add_action`、`add_filter` 注册的回调函数
- 插件主文件（`plugin-name.php`）
- 主题 `functions.php`

**CodeIgniter**:
- 文件路径包含 `application/controllers/` 或 `app/Controllers/`
- 继承 `CI_Controller` 或 `BaseController`

**Yii2**:
- 文件路径包含 `controllers/`
- 继承 `yii\web\Controller`

**通用**:
- 文件路径包含 `controller/`、`action/`、`handler/`、`route/`
- 文件名包含 `Controller`、`Action`、`Handler`
- 包含 `$_GET`、`$_POST`、`$_REQUEST` 直接访问的文件

### T2（业务逻辑层，权重 0.5）

Model、Service、Repository、Middleware、Helper —— 处理业务逻辑和数据访问的类。

**识别模式**:
- 文件路径包含 `model/`、`service/`、`repository/`、`middleware/`、`helper/`、`lib/`
- 文件名包含 `Model`、`Service`、`Repository`、`Middleware`、`Helper`、`Handler`
- Laravel Eloquent Model（继承 `Illuminate\Database\Eloquent\Model`）
- Doctrine Entity/Repository
- 文件路径包含 `template/`、`templates/`、`lang/`、`language/`、`theme/`、`plugin/`、`module/`、`resource/`、`cache/`
- 文件名包含 `Template`、`Localization`、`Loader`、`Renderer`、`Resource`、`Plugin`、`Theme`
- 公共函数库和包装层加载文件，如 `functions.php`、`functions.inc.php`

### T3（数据结构层，权重 0.1）

Entity、DTO、Request、Response —— 纯数据传输对象。

**识别模式**:
- 文件路径包含 `entity/`、`dto/`、`request/`、`response/`
- 文件名包含 `Entity`、`DTO`、`Request`、`Response`
- 仅包含属性声明和 getter/setter

### SKIP（不审计）

第三方库、供应商代码、生成代码、测试代码。

**排除模式**:
- 文件路径包含 `vendor/`、`node_modules/`、`tests/`、`test/`、`storage/`、`cache/`
- WordPress 核心文件（`wp-admin/`、`wp-includes/`）
- 框架核心（`vendor/laravel/`、`vendor/symfony/` 等）

**例外**:
- `lang/`、`language/`、`templates/`、`theme/`、`plugin/`、`module/`、`resource/`、`cache/`、`storage/` 下会被运行时 `include`、`require`、模板渲染或插件机制消费的 `.php`、`.inc`、`.phtml` 文件，至少归入 T2，不得直接 SKIP

## 框架检测

通过以下文件判断具体框架：
- Laravel: 存在 `artisan` 和 `composer.json` 中包含 `laravel/framework`
- Symfony: 存在 `bin/console` 和 `composer.json` 中包含 `symfony/`
- ThinkPHP: 存在 `thinkphp/` 目录或 `composer.json` 中包含 `topthink/framework`
- WordPress: 存在 `wp-config.php` 或 `wp-load.php`
- CodeIgniter: 存在 `system/` 目录和 `application/` 或 `app/` 目录
- Yii2: 存在 `vendor/yiisoft/yii2/`
