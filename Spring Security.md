# Spring Security 架构
本指南是Spring Secutity的入门，提供了对框架的设计和基本构建块的深入了解。我们只介绍了应用程序安全性的知识，
但是这样做可以消除使用Spring security的开发人员所经历的一些困惑。为了做到这一点，我们来看看在web应用程序中使用过滤器和更一般地使用方法注释
应用安全性的方式。当您需要在较高的层次上理解安全应用程序如何工作，以及如何指定它，或者仅仅需要学习如何考虑应用程序安全性时，使用本指南。

本指南不打算作为解决最基本问题的手册或秘方(还有其他来源)，但它对初学者和专家都很有用。Spring Boot也经常被提到，因为它为安全应用程序提供了一些默认行为，了解它如何适应整个体系结构非常有用。所有这些原则同样适用于不使用Spring Boot的应用程序。

-------------------------------------------

[TOC]

## Authentication and Access Control(身份验证和访问控制)
应用程序安全性归结为两个或多或少独立的问题:身份验证(您是谁?)和授权(允许您做什么?)有时人们会说“访问控制”而不是“授权”，这可能会让人感到困惑，但是这样想是有帮助的，因为“授权”在其他地方是重载的。Spring Security具有一种旨在将身份验证与授权分离的体系结构，并为这两种身份验证都提供了策略和扩展点。
### Authentication(身份验证)
Authentication的主要接口是`AuthenticationManager`，它只有一个方法
```java
public interface AuthenticationManager {

  Authentication authenticate(Authentication authentication)
    throws AuthenticationException;

}
```
`AuthenticationManager`可以在其`authenticate()`方法中执行三种操作之一：
 
 1.如果可以验证输入是否表示有效主体，则返回身份验证(通常为authenticated=true)。
 
 2.如果认为输入表示无效主题，则抛出`AuthenticationException`异常。
 
 3.如果不能决定返回null。
 
 `AuthenticationException`是一个运行时异常。
 它通常由应用程序以通用的方式处理，这取决于应用程序的风格或用途。换句话说，通常不期望用户代码捕捉和处理它。
 例如，web UI将呈现一个表示身份验证失败的页面，后端HTTP服务将发送401响应，
 是否使用`WWW-Authenticate`报头取决于上下文。
 
 `AuthenticationManager`最常用的实现是`ProviderManager`，它将委托给`AuthenticationProvider`实例链。
 `AuthenticationProvider`有点像`AuthenticationManager`，但是它有一个额外的方法，允许调用者查询它是否支持给定的`Authentication`类型:
 ```java
public interface AuthenticationProvider {

	Authentication authenticate(Authentication authentication)
			throws AuthenticationException;

	boolean supports(Class<?> authentication);

}
```
`Class<?>`在`supports()`方法中的参数实际上是`Class<? extends Authentication>`（只会询问它是否支持传递给`authenticate()`方法的内容）。
`ProviderManager`可以通过委托给`AuthenticationProviders`链，在同一个应用程序中支持多个不同的身份验证机制。如果`ProviderManager`不能识别特定的`Authentication`实例类型，
它将被跳过。

`ProviderManager`有一个可选的父节点，如果所有提供者返回`null`，它可以咨询该父节点。如果父类不可用，则`null Authentication`将导致`AuthenticationException`。

有时，应用程序具有受保护资源的逻辑组(例如，与路径模式`/api/**`匹配的所有web资源)，每个组也可以有自己专用的`AuthenticationManager`。通常，每一个都是`ProviderManager`，它们共享一个父类。
然后，父类是一种“全局”资源，充当所有提供者的备用资源。

![Image test](https://github.com/lfb0424/Spring-Security/blob/master/img/1.JPG)

### Customizing Authentication Managers（订制身份验证管理）
Spring Security提供了一些配置帮助程序，可以快速获得应用程序中设置的常用身份验证管理器特性。最常用的助手是`AuthenticationManagerBuilder`，它非常适合设置内存、JDBC或LDAP用户详细信息，或者添加自定义`UserDetailsService`。
下面是一个应用程序配置全局(父)`AuthenticationManager`的例子:
```java
@Configuration
public class ApplicationSecurity extends WebSecurityConfigurerAdapter {

   ... // web stuff here

  @Autowired
  public initialize(AuthenticationManagerBuilder builder, DataSource dataSource) {
    builder.jdbcAuthentication().dataSource(dataSource).withUser("dave")
      .password("secret").roles("USER");
  }

}
```
这个示例与web应用程序有关，但是`AuthenticationManagerBuilder`的使用更加广泛(有关如何实现web应用程序安全性的详细信息，请参阅下面的内容)。
请注意，`AuthenticationManagerBuilder`是`@Autowired`到`@Bean`中的方法中的—这就是它构建全局(parent)`AuthenticationManager`的原因。相反，如果我们这样做:
```java
@Configuration
public class ApplicationSecurity extends WebSecurityConfigurerAdapter {

  @Autowired
  DataSource dataSource;

   ... // web stuff here

  @Override
  public configure(AuthenticationManagerBuilder builder) {
    builder.jdbcAuthentication().dataSource(dataSource).withUser("dave")
      .password("secret").roles("USER");
  }

}
```
(使用配置器中方法的`@Override`)然后`AuthenticationManagerBuilder`只用于构建“本地”`AuthenticationManager`，它是全局`AuthenticationManager`的子方法。
在Spring引导应用程序中，您可以使用`@Autowired`将全局bean连接到另一个bean中，但是不能对本地bean这样做，除非您自己显式地公开它。

Spring Boot提供默认的全局`AuthenticationManager`(只有一个用户)，
除非您通过提供自己的`AuthenticationManager`类型的bean来先发制人。
默认值本身就足够安全，您不必太担心它，除非您需要自定义全局`AuthenticationManager`。
如果进行构建`AuthenticationManager`的任何配置，通常可以在本地对所保护的资源进行配置，
而不必担心全局默认值。
### Authorization or Access Control（授权或访问控制）
身份验证成功后，我们可以继续讨论`authorization`(授权)，这里的核心策略是`AccessDecisionManager`。
框架提供了三种实现，这三种实现都委托给`AccessDecisionVoter链`，
有点像`ProviderManager`委托给`AuthenticationProviders`。

`AccessDecisionVoter`考虑使用`ConfigAttributes`修饰的`Authentication`(表示主体)和安全`Object`:
```java
boolean supports(ConfigAttribute attribute);

boolean supports(Class<?> clazz);

int vote(Authentication authentication, S object,
        Collection<ConfigAttribute> attributes);
```
`Object`在`AccessDecisionManager`和`AccessDecisionVoter`的签名中是完全通用的——它表示用户可能想要访问的任何东西(Java类中的web资源或方法是最常见的两种情况)。
`ConfigAttributes`也是相当通用的，用一些元数据表示安全`Object`的修饰，这些元数据决定访问它所需的权限级别。
`ConfigAttribute`是一个接口，但是它只有一个非常通用的方法，并且返回一个`String`，所以这些字符串以某种方式编码了资源所有者的意图，表达关于谁可以访问它的规则。
典型的`ConfigAttribute`是用户角色的名称(如`ROLE_ADMIN`或`ROLE_AUDIT`)，它们通常有特殊的格式(如`ROLE_`前缀)或表示需要计算的表达式。

大多数人只使用默认的`AccessDecisionManager`，它是基于`AffirmativeBased`的(如果没有选民拒绝，那么就授予访问权)。任何定制都可能发生在投票者中，要么添加新的投票者，要么修改现有投票者的工作方式。

通常使用的`ConfigAttributes`是Spring Expression Language(SpEL)的表达式，例如`isFullyAuthenticated() && hasRole('FOO')`。
`AccessDecisionVoter`支持这种方法，它可以处理表达式并为它们创建上下文。
要扩展可以处理的表达式的范围，需要一个`SecurityExpressionRoot`的定制实现，有时还需要`SecurityExpressionHandler`。

## Web Secutity
web层中的Spring Security(对于ui和HTTP后端)是基于`Servlet Filter`的，因此通常首先查看筛选器的角色是有帮助的。下图显示了单个HTTP请求的处理程序的典型分层。

![Image test](https://github.com/lfb0424/Spring-Security/blob/master/img/2.JPG)

客户机向应用程序发送一个请求，container会根据请求URI的路径决定应用哪个filter和哪个servlet。
一个servlet最多只能处理一个request，但是filter形成了一个chain，所以它们是有序的，事实上，
如果filter想处理请求本身，它可以否决链的其余部分。filter还可以修改下游filter和servlet
中使用的request和/或response。过滤器链（filter chain）的顺序是非常重要的,和Spring Boot Manages通过两种机制:
一是`@ bean`类型的`Filter`有`@Order`或实现`Ordered接口`,另一个是他们可以成为`FilterRegistrationBean`的一部分,
它本身已经有了一种顺序作为API的一部分。一些现成的filters定义了它们自己的常量，以帮助指示它们喜欢的相对顺序
(例如，来自Spring Session的`SessionRepositoryFilter`具有`DEFAULT_ORDER` of `Integer.
MIN_VALUE + 50`，这告诉我们它喜欢在链的早期，但是它不排除在它之前的其他filter)。

Spring Secutity作为一个独立的Filter放在Chain种，它的具体类型是`FilterChainProxy`，原因很快就会很明显。
在Spring Boot应用程序中，security filter在`ApplicationContext`中以`@Bean`的形式存在，它是默认安装的，因此应用于每个请求。
它安装在`SecurityProperties.DEFAULT_FILTER_ORDER`定义的位置，它依次由`FilterRegistrationBean.REQUEST_WRAPPER_FILTER_MAX_ORDER`锚定。
(如果Filter来包裹request，修改其行为，Spring Boot应用程序期望Filter具有的最大顺序)。
但是，它的意义不止于此:从container的角度来看，Spring Security是一个Filter，但是在它内部还有其他Filter，每个Filter都扮演着特殊的角色。这里有一个图片:

![Image test](https://github.com/lfb0424/Spring-Security/blob/master/img/3.JPG)
图2。Spring Security是一个独立的物理`Filter`，但将处理委托给一个内部filter chain


实际上，security filter中甚至还有一个间接层:它通常作为一个`DelegatingFilterProxy`被安装在container中，它不一定是Spring `@Bean`。
代理委托给FilterChainProxy，它总是@Bean，通常有一个固定的名称叫做`springSecurityFilterChain`。
它是`FilterChainProxy`，FilterChainProxy包含所有的安全逻辑作为过滤器链(或多个链)在内部排列的。所有的Filter都有相同的API(它们都实现了Servlet规范中的`Filter`接口)，并且它们都有机会否决链的其余部分。

在相同级别的`FilterChainProxy`中，可以有多个由Spring Security管理的filter链，并且容器不知道这些过滤器链。
Spring Security filter包含filter chains的列表，并将请求发送给与之匹配的第一个链。
下图显示了基于匹配请求路径的发送(`/foo/**`匹配在`/**`之前)。这是非常常见的，但不是匹配请求的唯一方法。
这个发送过程最重要的特性是只有一个链处理请求。

![Image test](https://github.com/lfb0424/Spring-Security/blob/master/img/4.JPG)

图3。Spring Security `FilterChainProxy`将请求发送到匹配的第一个链。


一个没有自定义security configuration的普通Spring Boot application有n个filter chain，通常n=6。
第一个(n-1)链只是忽略静态资源模式，比如`/css/**`和`/images/**`，以及error view `/error`
(路径可以由用户通过来自`SecurityProperties`configuration bean 的 `security.ignored`控制)。
最后一个链匹配`/**(所有路径)`，并且更加活跃，包含身份验证、授权、异常处理、会话处理、header writing等逻辑。
默认情况下，这个链中总共有11个filter，但是用户通常不需要关心在什么时候使用哪些过滤器。

> Note:容器不知道Spring Security内部的所有filter，这一点非常重要，
特别是在Spring Boot application中，默认情况下，filter类型的所有
`@bean`都自动在容器中注册。因此，如果您想向security chain中添加自定义的过滤器，
您要么不把它注册成`@bean`，要么将其包装在`FilterRegistrationBean`中，
这样的话，该bean就会显式地禁用容器注册。

### Creating and Customizing Filter Chains(创建和定制Filter Chains)

Spring Boot应用程序(使用/**请求匹配器的应用程序)中的
默认fallback filter chain具有预定义的`SecurityProperties.BASIC_AUTH_ORDER`顺序（默认顺序）。
您可以通过设置`security.basic.enabled=false`来关闭它，或者您可以让它仅作为一种fallback，然后只定义其他低等级的order。
为此，只需添加类型为`WebSecurityConfigurerAdapter`(或`WebSecurityConfigurer`)的`@Bean`，并用`@Order`装饰这个类即可。
例如：
```java
@Configuration
@Order(SecurityProperties.BASIC_AUTH_ORDER - 10)
public class ApplicationConfigurerAdapter extends WebSecurityConfigurerAdapter {
  @Override
  protected void configure(HttpSecurity http) throws Exception {
    http.antMatcher("/foo/**")
     ...;
  }
}
```
这个bean将导致Spring Security添加一个新的filter chain，并在fallback之前对其进行排序。

许多应用程序对一组资源的访问规则与另一组资源的访问规则完全不同。
例如，承载UI和支持API的应用程序可能支持基于cookie的身份验证(重定向到UI部件的登录页面)，
以及基于令牌的身份验证(401响应未经过身份验证的API部件请求)。
每一组资源都有自己的`WebSecurityConfigurerAdapter`，具有唯一的顺序和自己的请求匹配器。
如果匹配规则重叠，排序最早的过滤链将获胜。

### Request Matching for Dispatch and Authorization(对于调用和授权的请求匹配)
Security filter chain(或者等价于`WebSecurityConfigurerAdapter`)有一个请求匹配器，用于决定是否将其应用于HTTP请求。一旦决定使用特定的filter chain，就不应用其他filter chain。但是在filter chain中，通过在`HttpSecurity`配置器中设置额外的匹配器，您可以对授权进行更细粒度的控制。例如：
```java
@Configuration
@Order(SecurityProperties.BASIC_AUTH_ORDER - 10)
public class ApplicationConfigurerAdapter extends WebSecurityConfigurerAdapter {
  @Override
  protected void configure(HttpSecurity http) throws Exception {
    http.antMatcher("/foo/**")
      .authorizeRequests()
        .antMatchers("/foo/bar").hasRole("BAR")
        .antMatchers("/foo/spam").hasRole("SPAM")
        .anyRequest().isAuthenticated();
  }
}
```

配置Spring Security最容易犯的错误之一是忘记这些匹配器适用于不同的进程，一个是整个filter chain的请求匹配器，另一个只是选择要应用的访问规则。

### Combining Application Security Rules With Actuator Rules
>将应用程序安全规则与执行器规则结合起来

如果您正在使用Spring Boot Actuator，那么您可能希望它们是安全的，并且默认情况下是安全的。
实际上，一旦将Actuator添加到secure application中，就会得到一个只应用于执行器端
点(actuator endpoints)的额外filter chain。它由一个只匹配执行器端点(actuator endpoints)的请求匹配器定义，
它的顺序是ManagementServerProperties.BASIC_AUTH_ORDER，这比默认的`SecurityProperties`fallback filter少5个，因此在fallback之前会咨询它。

如果你希望你的application security rules应用于执行器端点(actuator endpoints)，你可以添加比执行器（actuator）更早排序的
filter chain，并使用包含所有执行器端点的请求匹配器。如果您更喜欢执行器端点
的默认security设置，那么最简单的方法是在执行器（actuator）之后添加自己的filter，
但要早于fallback(例如`ManagementServerProperties.BASIC_AUTH_ORDER + 1`）。例如：
```java
@Configuration
@Order(ManagementServerProperties.BASIC_AUTH_ORDER + 1)
public class ApplicationConfigurerAdapter extends WebSecurityConfigurerAdapter {
  @Override
  protected void configure(HttpSecurity http) throws Exception {
    http.antMatcher("/foo/**")
     ...;
  }
}
```

>Note:web层中的Spring Security目前绑定到Servlet API，因此只有在Servlet容器中运行应用程序时才真正适用，
无论是嵌入式的还是其他的。然而，它并没有绑定到Spring MVC或Spring web堆栈的其他部分，
因此可以在任何servlet应用程序中使用它，例如使用JAX-RS的应用程序。

## Method Security(方法安全性)

Spring Security不仅支持保护web应用程序，还支持将访问规则应用于Java方法的执行。
对于Spring Security，这只是一种不同类型的“受保护资源”。
对于用户来说，这意味着使用相同格式的`ConfigAttribute` strings(例如角色或表达式)声明访问规则，但是在代码中的位置不同。
第一步是开启method security，例如在我们的应用程序的顶层配置中:
```java
@SpringBootApplication
@EnableGlobalMethodSecurity(securedEnabled = true)
public class SampleSecureApplication {
}
```
然后我们可以直接装饰方法资源，例如：
```java
@Service
public class MyService {

  @Secured("ROLE_USER")
  public String secure() {
    return "Hello Security";
  }

}
```

这个示例是一个具有secure method的service。
如果Spring创建了这种类型的`@Bean`，那么它将被代理，
调用者将不得不在方法实际执行之前通过security interceptor。
如果访问被拒绝，调用者将获得`AccessDeniedException`，而不是实际的方法结果。

这儿还有其他注释，这些注释可以被使用到方法上以达到强制执行安全约束
，特别是`@PreAuthorize`和`@PostAuthorize`，
它们允许您分别编写包含对方法参数和返回值的引用的表达式。

> Tip(小贴士):将Web安全性和method安全性结合起来并不少见。
filter chain提供了用户体验特性，如身份验证和重定向到登录页面等，
而方法安全性提供了更细粒度的保护。

## Working with Threads
Spring Security本质上是线程绑定的，因为它需要将当前经过身份验证的主体
提供给各种下游使用者。基本构建块是`SecurityContext`，它可能包含`Authentication`
(当用户登录时，它将是显式`authenticated`的`Authentication`)。您总是可以通过
`SecurityContextHolder`中静态的便利方法来访问和操作`SecurityContext`，
而`SecurityContext`会简单地操作`TheadLocal`。例如：
```java
SecurityContext context = SecurityContextHolder.getContext();
Authentication authentication = context.getAuthentication();
assert(authentication.isAuthenticated);
```

对于用户应用程序代码来说，这样做并不常见，
但是如果您需要编写自定义身份验证过滤器(authentication filter)
(即使这样，Spring Security中仍然有一些基类可以用于避免使用
`securitycontextHolder`的地方)，那么它还是很有用的。

如果你需要在web端访问当前身份验证通过的用户，你可以在`@RequestMapping`中使用method parameter。例如：
```java
@RequestMapping("/foo")
public String foo(@AuthenticationPrincipal User user) {
  ... // do stuff with user
}
```

该注释将当前`Authentication`从`SecurityContext`中提取出来，
并调用其中的`getPrincipal()`方法来生成方法参数。
`Authentication`中的`Principal`类型依赖于用于验证身份验证的`AuthenticationManager`，
因此这对于获取对用户数据的类型安全引用是一个有用的小技巧。

如果Spring Security正在使用具有`Authentication`类型的来自`HttpServletRequest`的`Principal`，
因此你也可以直接使用它：

```java
@RequestMapping("/foo")
public String foo(Principal principal) {
  Authentication authentication = (Authentication) principal;
  User = (User) authentication.getPrincipal();
  ... // do stuff with user
}
```

如果您需要编写能够正常工作的代码当Spring Security不使用时，
(您需要在加载`Authentication`类时更加谨慎)，那么这种方法有时非常有用。

### Processing Secure Methods Asynchronously(异步处理安全方法)
由于`SecurityContext`是线程绑定的，如果您希望执行
调用secure methods的任何
后台处理，例如使用`@Async`，您需要确保传播了上下文。
这可以归结为将`SecurityContext`包装为在后台执行的任务
(`Runnable`、`Callable`<可调用的>等等)。Spring Security提供了一些帮助来简化这一过程，
例如针对`Runnable`和`Callable`的wrappers<包装器>。
要将`SecurityContext`传播到`@Async`方法，
您需要提供一个`AsyncConfigurer`，并确保`Executor`的类型是正确的:
```java
@Configuration
public class ApplicationConfiguration extends AsyncConfigurerSupport {

  @Override
  public Executor getAsyncExecutor() {
    return new DelegatingSecurityContextExecutorService(Executors.newFixedThreadPool(5));
  }

}
```




