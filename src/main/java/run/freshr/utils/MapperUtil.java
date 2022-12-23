package run.freshr.utils;

import static org.modelmapper.Conditions.isNotNull;
import static org.modelmapper.convention.MatchingStrategies.STRICT;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.stream.Collectors;
import lombok.extern.slf4j.Slf4j;
import org.modelmapper.ModelMapper;

/**
 * ModelMapper Util
 *
 * @author FreshR
 * @apiNote ModelMapper 를 쉽게 사용하기 위한 Util
 * @since 2022. 12. 23. 오후 4:23:59
 */
@Slf4j
public class MapperUtil {

  /**
   * The Model mapper
   *
   * @apiNote ModelMapper 의존성 주입
   * @since 2022. 12. 23. 오후 4:23:59
   */
  static ModelMapper modelMapper;

  /*
   * ModelMapper 의존성 주입 및 설정
   */
  static {
    modelMapper = new ModelMapper();

    modelMapper
        .getConfiguration()
        .setPropertyCondition(isNotNull()) // Null 값 Binding 방지
        .setMatchingStrategy(STRICT); // 같은 타입의 필드명이 같은 경우만 동작
  }

  /**
   * 소스를 인스턴스에 맵핑
   *
   * @param <S>    값을 전달할 객체 Generic
   * @param <O>    값을 전달받을 객체 Generic
   * @param source 값을 전달할 객체
   * @param origin 값을 전달받을 객체의 Class
   * @return 값을 전달받은 객체
   * @apiNote 값을 전달할 객체 field 값을 변경될 객체 field 값에 binding<br>
   *          binding 전략은 설정에 따름
   * @author FreshR
   * @since 2022. 12. 23. 오후 4:23:59
   */
  public static <S, O> O map(final S source, final Class<O> origin) {
    log.debug("MapperUtil.map");
    log.debug("source = " + source + ", origin = " + origin);

    O result = null;

    try {
      result = modelMapper.map(source, origin);
    } catch (Exception e) {
      e.printStackTrace();
    }

    log.debug("result = " + result);

    return result;
  }

  /**
   * 소스를 인스턴스에 맵핑
   *
   * @param <S>    값을 전달할 객체
   * @param <O>    값을 전달받을 객체
   * @param source 값을 전달할 객체
   * @param origin 값을 전달받을 객체
   * @return 값을 전달받은 객체
   * @apiNote 값을 전달할 객체 field 값을 변경될 객체 field 값에 binding<br>
   *          binding 전략은 설정에 따름
   * @author FreshR
   * @since 2022. 12. 23. 오후 4:23:59
   */
  public static <S, O> O map(final S source, final O origin) {
    log.debug("MapperUtil.map");
    log.debug("source = " + source + ", origin = " + origin);

    try {
      modelMapper.map(source, origin);
    } catch (Exception e) {
      e.printStackTrace();
    }

    log.debug("result = " + origin);

    return origin;
  }

  /**
   * 소스를 인스턴스에 맵핑
   *
   * @param <S>    값을 전달할 객체
   * @param <O>    값을 전달받을 객체
   * @param list   값을 전달할 객체 목록
   * @param origin 값을 전달받을 객체의 Class
   * @return 값을 전달받은 객체 목록
   * @apiNote 값을 전달할 객체 field 값을 변경될 객체 field 값에 binding 후 목록으로 반환<br>
   *          binding 전략은 설정에 따름
   * @author FreshR
   * @since 2022. 12. 23. 오후 4:23:59
   */
  public static <S, O> List<S> map(final Collection<O> list, final Class<S> origin) {
    log.debug("MapperUtil.map");
    log.debug("list = " + list + ", origin = " + origin);

    List<S> result = new ArrayList<>();

    try {
      result = list
          .stream()
          .map(item -> map(item, origin))
          .collect(Collectors.toList());
    } catch (Exception e) {
      e.printStackTrace();
    }

    log.debug("result = " + result);

    return result;
  }

}
