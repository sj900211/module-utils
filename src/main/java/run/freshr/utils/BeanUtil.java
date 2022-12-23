package run.freshr.utils;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextAware;
import org.springframework.stereotype.Component;

/**
 * Bean Util
 *
 * @author FreshR
 * @apiNote Bean 으로 등록된 객체를 의존성 주입이 되어있지 않은 Class 에서 사용하기 위한 Util
 * @since 2022. 12. 23. 오후 4:23:59
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class BeanUtil implements ApplicationContextAware {

  /**
   * Application Context
   *
   * @apiNote Bean 객체를 생성하고 관리하는 기능을 가지고 있는 객체<br>
   *          컨테이너가 구동되는 시점에 객체들을 생성하는 Pre-Loading 방식을 사용하고 있다.
   * @since 2022. 12. 23. 오후 4:23:59
   */
  private static ApplicationContext context;

  /**
   * Bean 객체 조회
   *
   * @param <T>   조회할 Bean 객체
   * @param clazz 조회할 Bean 객체 Class
   * @return the bean
   * @apiNote Bean 객체 조회
   * @author FreshR
   * @since 2022. 12. 23. 오후 4:23:59
   */
  public static <T> T getBean(final Class<T> clazz) {
    log.debug("BeanUtil.getBean");
    log.debug("clazz = " + clazz);

    T result = context.getBean(clazz);

    log.debug("result = " + result);

    return result;
  }

  /**
   * Bean 객체 조회
   *
   * @param beanName 조회할 Bean 객체의 Simple Name
   * @return the bean
   * @apiNote Bean 객체 조회
   * @author FreshR
   * @since 2022. 12. 23. 오후 4:23:59
   */
  public static Object getBean(final String beanName) {
    log.debug("BeanUtil.getBean");
    log.debug("beanName = " + beanName);

    Object result = context.getBean(beanName);

    log.debug("result = " + result);

    return result;
  }

  /**
   * ApplicationContext 주입
   *
   * @param context ApplicationContext
   * @apiNote ApplicationContext 에 접근하기 위해서는<br>
   *          ApplicationContextAware 를 상속받아 구현해야 한다.<br>
   *          ApplicationContextAware.setApplicationContext 메서드를 통해서<br>
   *          ApplicationContext 를 주입시킨다.
   * @author FreshR
   * @since 2022. 12. 23. 오후 4:23:59
   */
  @Override
  public void setApplicationContext(final ApplicationContext context) {
    log.debug("BeanUtil.setApplicationContext");
    log.debug("context = " + context);

    BeanUtil.context = context;
  }

}
